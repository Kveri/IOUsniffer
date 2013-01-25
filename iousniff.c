/*
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <poll.h>
#include <pcap.h>

#define SOCKET_DIR "/tmp/netio0"
#define NETMAP_FILE "/home/kveri/iou_test/NETMAP"

struct instances_s {
	struct iou_s *ious;
	struct pollfd *sockets;
	int niou;
};

struct sniff_s {
	int if_major;
	int if_minor;
	
	pcap_t *ph;
	pcap_dumper_t *pd;
	
	struct sniff_s *next;
};

struct iou_s {
	int instance_id;
	int sock;
	struct sniff_s *sniffs;
	
	struct iou_s *next;
};

void rebuild_fds(struct instances_s *obj)
{
	int i = 0;
	struct iou_s *iou_ptr = obj->ious;
	obj->sockets = (struct pollfd *)realloc(obj->sockets,
			sizeof(struct pollfd) * (obj->niou));
	printf("fds realloc: %d\n", obj->niou);

	while (iou_ptr) {
		printf("adding socket %d to index %d\n", iou_ptr->sock, i);
		obj->sockets[i].fd = iou_ptr->sock;
		obj->sockets[i].events = POLLIN;
		iou_ptr = iou_ptr->next;
		i++;
	}
}

struct sniff_s *parse_netmap(int iou_id)
{
	char id[10], line[4096];
	FILE *fp;
	int if_major, if_minor;
	char *c;

	printf("parsing for id=%d\n", iou_id);

	sprintf(id, "%d:", iou_id);
	fp = fopen(NETMAP_FILE, "r");
	while (!feof(fp)) {
		c = fgets(line, sizeof(line), fp);
		if (!c)
			break;
		c = strstr(line, id);
		if (!c)
			continue;
		
		// c should be at line beggining or after ' ' (space)
		if (c != line && c[-1] != ' ' && c[-1] != '\t')
			continue;

		c += strlen(id);

		if_major = (int)strtol(c, &c, 10);
		c++;
		if_minor = (int)strtol(c, &c, 10);
		printf("iou: %d\n", iou_id);
		printf("MAJOR: '%d'\n", if_major);
		printf("MINOR: '%d'\n", if_minor);
	}

	fclose(fp);

	return NULL;
}

void sniff_init(struct iou_s *iou)
{
	iou->sniffs = parse_netmap(iou->instance_id);
}

void iou_add(struct instances_s *obj, struct iou_s *iou_new)
{
	struct iou_s *iou_ptr;

	iou_new->next = NULL;
	if (!obj->ious) {
		obj->ious = iou_new;
		goto out;
	}
	iou_ptr = obj->ious;
	while (iou_ptr && iou_ptr->next)
		iou_ptr = iou_ptr->next;
	iou_ptr->next = iou_new;
out:
	obj->niou++;
	sniff_init(iou_new);
}

int socket_replace(char *name)
{
	struct sockaddr_un sock_addr;
	int tmp, sock;
	char path_tmp[PATH_MAX];

	sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	sock_addr.sun_family = AF_UNIX;
	strcpy(sock_addr.sun_path, SOCKET_DIR);
	strcat(sock_addr.sun_path, "/");
	strcat(sock_addr.sun_path, name);
	tmp = strlen(sock_addr.sun_path) + sizeof(sock_addr.sun_family);

	strcpy(path_tmp, sock_addr.sun_path);
	strcat(path_tmp, "_real");
	rename(sock_addr.sun_path, path_tmp);
	bind(sock, (struct sockaddr *)&sock_addr, tmp);

	return sock;
}

void instance_add(struct instances_s *obj, char *name)
{
	struct iou_s *iou_new;

	iou_new = (struct iou_s *)malloc(sizeof(struct iou_s));
	iou_new->instance_id = atoi(name);
	iou_new->sock = socket_replace(name);

	iou_add(obj, iou_new);
	rebuild_fds(obj);
}

int check_files(struct instances_s *obj)
{
	DIR *dir;
	struct dirent *entry;
	struct iou_s *iou_ptr;
	int got_it;

	dir = opendir(SOCKET_DIR);
	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_type != DT_SOCK)
			continue; // only socket files interest us
		if (strstr(entry->d_name, "_real") != NULL)
			continue; // ignore real sockets

		iou_ptr = obj->ious;
		got_it = 0;
		while (iou_ptr) {
			// walk instances, look for current socket
			if (iou_ptr->instance_id == atoi(entry->d_name)) {
				got_it = 1;
				break;
			}
			iou_ptr = iou_ptr->next;
		}
		if (got_it != 1)
			instance_add(obj, entry->d_name);
	}
	closedir(dir);
	return 0;
}

void init_obj(struct instances_s *obj)
{
	obj->ious = NULL;
	obj->sockets = NULL;
	obj->niou = 0;
}

void handle_incoming(struct instances_s *obj, int index)
{
	struct sockaddr_un remote, dst;
	char buf[65536], path[PATH_MAX];
	unsigned int remote_len, iou_dst, iou_src, iou_src_if1, iou_src_if2;
	unsigned int iou_dst_if1, iou_dst_if2;
	int len, i;

	remote_len = sizeof(remote);
	len = recvfrom(obj->sockets[index].fd, &buf, sizeof(buf), 0,
			(struct sockaddr *)&remote, &remote_len);

	if (len < 8) // invalid packet
		return;

	// conversion
	iou_dst = ntohs(*((short *)&buf[0]));
	iou_src = ntohs(*((short *)&buf[2]));
	iou_dst_if1 = buf[4] & 0x0f;
	iou_dst_if2 = (buf[4] & 0xf0) >> 4;
	iou_src_if1 = buf[5] & 0x0f;
	iou_src_if2 = (buf[5] & 0xf0) >> 4;

	// build path and send it
	sprintf(path, "%s/%d_real", SOCKET_DIR, iou_dst);

	dst.sun_family = AF_UNIX;
	strncpy(dst.sun_path, path, sizeof(dst.sun_path)-1);
	sendto(obj->sockets[index].fd, buf, len, 0,
			(struct sockaddr *)&dst, sizeof(dst));

	// dump it
	printf("received from [%s] ", remote.sun_path);
	printf("%d:%d/%d -> %d:%d/%d:\n", iou_src, iou_src_if1,
			iou_src_if2, iou_dst, iou_dst_if1, iou_dst_if2);
	for (i = 0; i < len; i++) {
		printf("%02X ", buf[i] & 0xff);
	}
	printf("\n");
}

int main()
{
	struct instances_s obj;
	int i, ret;
	
	init_obj(&obj);

	while (1) {
		// TODO: every 5 seconds at most
		check_files(&obj);

		ret = poll(obj.sockets, obj.niou, -1);
		if (ret <= 0)
			continue;

		for (i = 0; i < obj.niou && ret != 0; i++) {
			if (obj.sockets[i].revents != POLLIN)
				continue;

			handle_incoming(&obj, i);
			ret--;
		}
	}
}
