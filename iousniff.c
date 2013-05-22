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
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <poll.h>
#include <time.h>
#include <signal.h>
#include <pcap.h>

#include "config.h"
#include "misc.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define IOUHDR_LEN 8

int SIGNAL_END = 0;

struct instances_s {
	struct iou_s *ious;
	struct pollfd *sockets;
	int niou;
};

struct sniff_s {
	int iou_id1;
	int iou_id2;
	int if_major1;
	int if_minor1;
	int if_major2;
	int if_minor2;
	int if_dlt; // data link type (http://www.tcpdump.org/linktypes.html)
	
	pcap_t *ph;
	pcap_dumper_t *pd;
	
	struct sniff_s *next;
};

struct iou_s {
	int instance_id;
	int sock;
	struct sniff_s *sniffs;
	int nsniff;
	
	struct iou_s *next;
};

void rebuild_fds(struct instances_s *obj)
{
	int i = 0;
	struct iou_s *iou_ptr = obj->ious;

	obj->sockets = (struct pollfd *)realloc(obj->sockets,
			sizeof(struct pollfd) * (obj->niou));

	while (iou_ptr) {
		obj->sockets[i].fd = iou_ptr->sock;
		obj->sockets[i].events = POLLIN;
		iou_ptr = iou_ptr->next;
		i++;
	}
}

void delete_sniff(struct iou_s *iou, int iou_id1, int if_major1, int if_minor1, int iou_id2, int if_major2, int if_minor2)
{
	struct sniff_s *sniff_ptr;
	struct sniff_s *sniff_before;
	
	if(iou->nsniff == 0) // no sniffer attached to the IOU
		return;
	
	if(iou->nsniff == 1) // only one sniffer attached to the IOU
	{
		sniff_ptr = iou->sniffs;
		
		if(sniff_ptr->iou_id1 == iou_id1 && sniff_ptr->iou_id2 == iou_id2 && sniff_ptr->if_major1 == if_major1 && sniff_ptr->if_major2 == if_major2 && sniff_ptr->if_minor1 == if_minor1 && sniff_ptr->if_minor2 == if_minor2)
		{
			debug(1,"Link to supress : %d:%d/%d %d:%d/%d\n",iou_id1,if_major1,if_minor1,iou_id2,if_major2,if_minor2);
			pcap_dump_close(sniff_ptr->pd);
			pcap_close(sniff_ptr->ph);
			
			free(sniff_ptr);
			iou->sniffs = NULL;
			
			iou->nsniff--;
			return;
		}
	}
	else if(iou->nsniff > 1) // more than one sniffer attached the IOU
	{
		sniff_ptr = iou->sniffs->next;
		sniff_before = iou->sniffs;
		
		while(sniff_ptr)
		{
			if(sniff_ptr->iou_id1 == iou_id1 && sniff_ptr->iou_id2 == iou_id2 && sniff_ptr->if_major1 == if_major1 && sniff_ptr->if_major2 == if_major2 && sniff_ptr->if_minor1 == if_minor1 && sniff_ptr->if_minor2 == if_minor2)
			{
				debug(1,"Link to supress : %d:%d/%d %d:%d/%d\n",iou_id1,if_major1,if_minor1,iou_id2,if_major2,if_minor2);
				
				pcap_dump_close(sniff_ptr->pd);
				pcap_close(sniff_ptr->ph);
				
				if(sniff_ptr->next != NULL)
				{
					sniff_before->next = sniff_ptr->next;
				}
				else
				{
					sniff_before->next = NULL;
				}
				free(sniff_ptr);
				
				iou->nsniff--;
				return;
			}
			sniff_ptr = sniff_ptr->next;
			sniff_before = sniff_ptr;
		}
	}
}

void create_sniff(struct iou_s *iou, int iou_id1, int if_major1, int if_minor1, int iou_id2, int if_major2, int if_minor2, int if_dlt)
{
	char file[PATH_MAX];

	struct sniff_s *sniff_ptr;
	struct sniff_s *sniff_new;
	int sniff_link = 0;
	
	sniff_ptr = iou->sniffs;

	while(sniff_ptr) //check if we have alreay a sniffer for the link
	{
		if(sniff_ptr->iou_id1 == iou_id1 && sniff_ptr->iou_id2 == iou_id2 && sniff_ptr->if_major1 == if_major1 && sniff_ptr->if_major2 == if_major2 && sniff_ptr->if_minor1 == if_minor1 && sniff_ptr->if_minor2 == if_minor2)
		{
			debug(2,"Sniffer for link between %d:%d/%d and %d:%d/%d alreay found\n", iou_id1, if_major1, if_minor1, iou_id2, if_major2, if_minor2);
			sniff_link++;
			break;
		}
		sniff_ptr = sniff_ptr->next;
	}
	
	if(sniff_link == 0) // if no sniffer found
	{
		debug(0,"creating sniffer for link between %d:%d/%d and %d:%d/%d\n", iou_id1, if_major1, if_minor1, iou_id2, if_major2, if_minor2);
		sprintf(file, "%s/%d_%d.%d-%d_%d.%d-%ld.pcap", config.sniff_dir, iou_id1, if_major1, if_minor1,iou_id2, if_major2, if_minor2, time(NULL));

		sniff_new = (struct sniff_s *)malloc(sizeof(struct sniff_s));

		sniff_new->iou_id1 = iou_id1;
		sniff_new->if_major1 = if_major1;
		sniff_new->if_minor1 = if_minor1;
		sniff_new->iou_id2 = iou_id2;
		sniff_new->if_major2 = if_major2;
		sniff_new->if_minor2 = if_minor2;
		sniff_new->if_dlt = if_dlt;
		sniff_new->next = NULL;
		sniff_new->ph = pcap_open_dead(if_dlt, 65535);
		sniff_new->pd = pcap_dump_open(sniff_new->ph, file);
		if (!sniff_new->pd) {
			printf("pcap error: %s\n", pcap_geterr(sniff_new->ph));
		}

		//assign the sniffer to the list
		if (!iou->sniffs) {
			iou->sniffs = sniff_new;
		}
		else {
			sniff_ptr = iou->sniffs;
			while (sniff_ptr && sniff_ptr->next)
				sniff_ptr = sniff_ptr->next;
			sniff_ptr->next = sniff_new;
		}
		iou->nsniff++;
	}

}

struct iou_s *parse_half_line(char **cp,int check_device, struct instances_s *obj, int *iou_id1, int *if_major, int *if_minor)
{
	char *c = *cp;
	int x, if1, if2;
	int iou_in_obj = 0;
	struct iou_s *iou_ptr = obj->ious;
	
	// 100:0/0@test1 101:0/1@test1 #1
	// 100:0/0@test1 101:0/1@test1 #104
	// 100:0/0@test1 101:0/1@test1
	
	x = (int)strtol(c, &c, 10); //parse the first IOU ID

	while(iou_ptr) //check if the IOU ID is in the list of registered IOU
	{
		if(iou_ptr->instance_id == x)
		{
			iou_in_obj++;
			break;
		}
		iou_ptr = iou_ptr->next;
	}
	if(iou_in_obj == 0 && check_device == 1) // if not found in the list of registered IOU
		return NULL;

	if (*c != ':') // invalid line
		return NULL;
	c++;
	
	if1 = (int)strtol(c, &c, 10);
	if (*c != '/')
		return NULL;
	c++;

	if2 = (int)strtol(c, &c, 10);


	*iou_id1 = x;
	*if_major = if1;
	*if_minor = if2;
	*cp = c;
	return iou_ptr;
}

void parse_dlt(char **cp, int *if_dlt)
{
	char *c = *cp;
	*if_dlt = (int)strtol(c, &c, 10);
}

void parse_one_line(char *line, struct instances_s *obj)
{
	char *c = line;
	int iou_id1, iou_id2, if_major1, if_minor1, if_major2, if_minor2, if_dlt;
	struct iou_s *ret1, *ret2;
	// 100:0/0@test1 101:0/1@test1 #1
	// 100:0/0@test1 101:0/1@test1 #104
	// 100:0/0@test1 101:0/1@test1
	
	if(need_capture_line(line)) //if we found a specific DLT
	{
		ret1 = parse_half_line(&c, 1, obj, &iou_id1, &if_major1, &if_minor1); //check for the existence of the IOU

		if (ret1 == NULL) {
			debug(0, "invalid line or IOU ID not found in registered IOU\n");
			return; // invalid line or IOU not found in the registered IOU
		}

		// find first space (or an end)
		c = strpbrk(c, " \t\r\n");
		if (!c || *c == '\r' || *c == '\n') {
			debug(0, "invalid line (premature end of line)\n");
			return; // invalid line (premature end of line)
		}
		// eat spaces
		while (*c == ' ' || *c == '\t')
			c++;

		ret2 = parse_half_line(&c, 0, obj, &iou_id2, &if_major2, &if_minor2); //don't check for the existence of the IOU

		// find first space (or an end) 
		c = strpbrk(c, " \t\r\n");
		if (!c || *c == '\r' || *c == '\n') { // found end
			debug(0, "no DLT found (premature end of line)\n");
			return;
		}
		c++;
		
		if(!c || *c != '#') {
			debug(2, "no DLT found (wrong format '#DTL')\n");
			return;
		}
		c++;
		
		parse_dlt(&c, &if_dlt);

		if (ret1) // create a sniffer structure only if the first IOU in the NETMAP line is registered
			create_sniff(ret1, iou_id1, if_major1, if_minor1, iou_id2, if_major2, if_minor2, if_dlt);
	}
	else // if DLT not found we may have to delete a sniffer
	{
		ret1 = parse_half_line(&c, 1, obj, &iou_id1, &if_major1, &if_minor1); //check for the existence of the IOU

		if (ret1 == NULL) {
			debug(1, "invalid line or IOU ID not found in registered IOU\n");
			return; // invalid line
		}

		// find first space (or an end)
		c = strpbrk(c, " \t\r\n");
		if (!c || *c == '\r' || *c == '\n') {
			debug(0, "invalid line (premature end of line)\n");
			return; // invalid line (premature end of line)
		}
		// eat spaces
		while (*c == ' ' || *c == '\t')
			c++;

		ret2 = parse_half_line(&c, 0, obj, &iou_id2, &if_major2, &if_minor2); //don't check for the existence of the IOU
		
		if(ret1)
			delete_sniff(ret1, iou_id1, if_major1, if_minor1, iou_id2, if_major2, if_minor2);
	}
}

void parse_netmap(struct instances_s *obj)
{
	FILE *fp;
	char id[10], line[4096], *c;
	int ret;

	fp = fopen(config.netmap_file, "r");
	if (!fp) {
		perror("NETMAP fopen");
		return;
	}
	while (!feof(fp)) {
		c = fgets(line, sizeof(line), fp);
		if (!c)
			break;

		debug(2, "parser read line: %s", line);
		parse_one_line(line, obj);
	}

	ret = fclose(fp);
	if (ret != 0) {
		perror("NETMAP fclose");
		return;
	}
}

int iou_add(struct instances_s *obj, struct iou_s *iou_new)
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

	return 0;
}

int socket_replace(char *name)
{
	struct sockaddr_un sock_addr;
	char path_tmp[PATH_MAX];
	int tmp, sock, ret;

	sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sock == -1) {
		perror("socket failed");
		return -1;
	}

	sock_addr.sun_family = AF_UNIX;
	strcpy(sock_addr.sun_path, config.netio_dir);
	strcat(sock_addr.sun_path, "/");
	strcat(sock_addr.sun_path, name);
	tmp = strlen(sock_addr.sun_path) + sizeof(sock_addr.sun_family);

	strcpy(path_tmp, sock_addr.sun_path);
	strcat(path_tmp, "_real");
	ret = rename(sock_addr.sun_path, path_tmp);
	if (ret == -1) {
		perror("rename failed");
		return -1;
	}
	ret = bind(sock, (struct sockaddr *)&sock_addr, tmp);
	if (ret == -1) {
		perror("bind failed");
		return -1;
	}

	return sock;
}

void iou_free(struct iou_s *iou_ptr)
{
	char path[PATH_MAX], path_real[PATH_MAX], path_lock[PATH_MAX];
	struct sniff_s *sniff_ptr, *sniff_ptr2;
	int fd;
	struct flock lock;

	debug(0, "Freeing IOU %d\n", iou_ptr->instance_id);

	close(iou_ptr->sock);
	sprintf(path, "%s/%d", config.netio_dir, iou_ptr->instance_id);
	strcpy(path_real, path);
	strcat(path_real, "_real");
	// first try to remove socket base socket
	if (unlink(path)) {
		// if it fails it means IOU has finished
		// so we cleanup and remove real socket completely
		unlink(path_real);
	} else {
		// if it exists IOU should be running
		// but thanks to poor practices in wrapper-linux
		// which kills IOU with SIGKILL, socket could exists
		// without IOU actually running

		// first we try to open lockfile, if we fail IOU is 100% down
		// because its lockfile has been removed and we can safely
		// remove real socket
		strcpy(path_lock, path);
		strcat(path_lock, ".lck");
		fd = open(path_lock, O_WRONLY);
		if (fd < 0) {
			unlink(path_real);
		} else {
			// IOU was improperly shutted down or it's running
			// now we try to obtain a WR lock just like IOU does
			lock.l_type = F_WRLCK;
			lock.l_whence = SEEK_END;
			lock.l_start = 0;
			lock.l_len = 0;
			lock.l_pid = 0;
			fcntl(fd, F_GETLK, &lock); // fcntl always returns 0
			close(fd);
			if (lock.l_type == F_UNLCK) {
				// lockfile isn't locked means IOU isn't running
				unlink(path_real);
				unlink(path_lock);
			} else {
				// lockfile is locked, so IOU is running
				rename(path_real, path);
			}
		}
	}

	sniff_ptr = iou_ptr->sniffs;
	while (sniff_ptr) {
		pcap_dump_close(sniff_ptr->pd);
		pcap_close(sniff_ptr->ph);
		sniff_ptr2 = sniff_ptr->next;
		free(sniff_ptr);
		sniff_ptr = sniff_ptr2;
	}

	free(iou_ptr);
}

int instance_add(struct instances_s *obj, char *name)
{
	struct iou_s *iou_new;
	int ret;

	debug(4, "instance_add(%p, %s)\n", obj, name);

	iou_new = (struct iou_s *)malloc(sizeof(struct iou_s));
	iou_new->instance_id = atoi(name);
	iou_new->sock = socket_replace(name);
	iou_new->sniffs = NULL;
	iou_new->nsniff = 0;
	
	if (iou_new->sock < 0) {
		free(iou_new);
		return iou_new->sock;
	}

	ret = iou_add(obj, iou_new);
	if (ret == -1) {
		debug(0, "NOT Registered IOU %s (not found in NETMAP)\n", name);
		return -1;
	}

	debug(0, "Registered IOU %s\n", name);
	return 0;
}

struct iou_s *instance_remove(struct instances_s *obj, int iou_id)
{
	struct iou_s *iou_ptr = obj->ious, *iou_prev;

	while (iou_ptr) {
		if (iou_ptr->instance_id != iou_id) {
			iou_prev = iou_ptr;
			iou_ptr = iou_ptr->next;
			continue;
		}

		if (iou_ptr == obj->ious) {
			obj->ious = iou_ptr->next;
			iou_prev = NULL;
		} else {
			iou_prev->next = iou_ptr->next;
		}
		iou_free(iou_ptr);
		break;
	}
	return iou_prev ? iou_prev->next : obj->ious;
}

int check_files(struct instances_s *obj)
{
	DIR *dir;
	struct dirent *entry;
	struct iou_s *iou_ptr;
	char path[PATH_MAX];
	int got_it, ret, name, need_refresh = 0;
	struct stat st;

	dir = opendir(config.netio_dir);
	if (!dir) {
		perror("opendir failed");
		return -1;
	}

	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_type != DT_SOCK)
			continue; // only socket files interest us
		if (strstr(entry->d_name, "_real") != NULL)
			continue; // ignore real sockets
			
		name = atoi(entry->d_name); //check the ID of the socket
		if (name == 0 || name > 1000) { // if > 1000 don't register (ioulive86)
			debug(2, "skipping ioulive id : %d\n", name);
			continue;
		}
		
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
		if (got_it != 1) {
			ret = instance_add(obj, entry->d_name);
			if (ret == 0) {
				need_refresh = 1;
			}
		}
	}
	ret = closedir(dir);
	if (ret) {
		perror("closedir failed");
		return ret;
	}
	
	// parse the netmap file checking for link to capture or stop capturing
	// only line with 2 connections and a pattern #dlt at the end of the line are captured
	parse_netmap(obj);
	
	// check our sockets if they still exist
	// if not, IOU instance has finished and we need to remove our socket
	iou_ptr = obj->ious;
	while (iou_ptr) {
		sprintf(path, "%s/%d", config.netio_dir, iou_ptr->instance_id);
		ret = stat(path, &st);
		if (ret == 0) {
			iou_ptr = iou_ptr->next;
			continue;
		}
		debug(0, "Socket for IOU %d gone, removing instance\n",
													iou_ptr->instance_id);
		iou_ptr = instance_remove(obj, iou_ptr->instance_id);
		debug(0, "Instance removed\n");
		need_refresh = 1;
	}
	if (need_refresh) {
		debug(1, "Refreshing poll sockets\n");
		rebuild_fds(obj);
	}
	return 0;
}

void init_obj(struct instances_s *obj)
{
	obj->ious = NULL;
	obj->sockets = NULL;
	obj->niou = 0;
}

void pcap_write(struct instances_s *obj, int dst, int dst_if1, int dst_if2,
					int src, int src_if1, int src_if2, char *buf, int len)
{
	struct pcap_pkthdr hdr;
	struct timeval tv;
	struct iou_s *iou_ptr;
	struct sniff_s *sniff_ptr;
	int x, x1, x2;

	gettimeofday(&tv, NULL);
	memcpy(&(hdr.ts), &tv, sizeof(tv));
	hdr.caplen = len;
	hdr.len = len;

	iou_ptr = obj->ious;
	x = -1;
	debug(3,"PCAP : src --> %d , dst --> %d\n", src, dst);
	while (iou_ptr) {
		if (iou_ptr->instance_id == dst) {
			x = dst;
			x1 = dst_if1;
			x2 = dst_if2;
		}
		if (iou_ptr->instance_id == src) {
			x = src;
			x1 = src_if1;
			x2 = src_if2;
		}
		if (x == -1) {
			debug(3,"PCAP not found\n");
		}
			goto next;

		x = -1;
		sniff_ptr = iou_ptr->sniffs;
		while (sniff_ptr) {
			if (sniff_ptr->if_major1 != x1 || sniff_ptr->if_minor1 != x2)
				goto next2;

			pcap_dump((u_char *)sniff_ptr->pd, &hdr, (u_char *)buf);
			if (config.flush_at_write == 1)
				pcap_dump_flush(sniff_ptr->pd);

next2:
			sniff_ptr = sniff_ptr->next;
		}
next:
		iou_ptr = iou_ptr->next;
	}
}

void handle_incoming(struct instances_s *obj, int index)
{
	struct sockaddr_un remote, dst;
	char buf[65536], path[PATH_MAX];
	unsigned int remote_len, iou_dst, iou_src, iou_src_if1, iou_src_if2;
	unsigned int iou_dst_if1, iou_dst_if2;
	int len, ret;

	remote_len = sizeof(remote);
	len = recvfrom(obj->sockets[index].fd, &buf, sizeof(buf), 0,
			(struct sockaddr *)&remote, &remote_len);

	if (len < IOUHDR_LEN) // invalid packet
		return;

	// conversion
	iou_dst = ntohs(*((short *)&buf[0]));
	iou_src = ntohs(*((short *)&buf[2]));
	iou_dst_if1 = buf[4] & 0x0f;
	iou_dst_if2 = (buf[4] & 0xf0) >> 4;
	iou_src_if1 = buf[5] & 0x0f;
	iou_src_if2 = (buf[5] & 0xf0) >> 4;

	// build path and send it
	sprintf(path, "%s/%d_real", config.netio_dir, iou_dst);

	dst.sun_family = AF_UNIX;
	strncpy(dst.sun_path, path, sizeof(dst.sun_path)-1);
	ret = sendto(obj->sockets[index].fd, buf, len, 0,
			(struct sockaddr *)&dst, sizeof(dst));
	if (ret == -1) {
		perror("sendto failed");
		// close this instance
		debug(0, "Can't write to socket %d, removing instance\n", iou_dst);
		instance_remove(obj, iou_dst);
		rebuild_fds(obj);

		return;
	}

	pcap_write(obj, iou_dst, iou_dst_if1, iou_dst_if2, iou_src, iou_src_if1,
							iou_src_if2, buf+IOUHDR_LEN, len-IOUHDR_LEN);

	// dump it
	debug(2, "%d:%d/%d -> %d:%d/%d len=%d\n", iou_src, iou_src_if1,
			iou_src_if2, iou_dst, iou_dst_if1, iou_dst_if2, len-IOUHDR_LEN);

	if (config.debug_level >= 3)
		dump_packet(buf+IOUHDR_LEN, len-IOUHDR_LEN);
}

void signal_handler(int signum)
{
	debug(0, "Cleaning up...\n");
	SIGNAL_END = 1;
}

void end_process(struct instances_s *obj)
{
	struct iou_s *iou_ptr, *iou_ptr2;

	if (obj->ious) {
		iou_ptr = obj->ious;
		while (iou_ptr) {
			iou_ptr2 = iou_ptr->next;
			iou_free(iou_ptr);
			iou_ptr = iou_ptr2;
		}
	}

	free(obj->sockets);
	free(config.netio_dir);
	free(config.netmap_file);
	free(config.sniff_dir);

	exit(0);
}

int main(int argc, char *argv[], char *envp[])
{
	struct instances_s obj;
	int i, ret;
#define CHECK_INTERVAL 5
	time_t last_time = time(NULL) - CHECK_INTERVAL - 1;
	
	init_obj(&obj);

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGHUP, signal_handler);

	ret = parse_arguments(argc, argv, envp);
	if (ret)
		return ret;

	printf("NETMAP: %s\n", config.netmap_file);
	printf("Netio directory: %s\n", config.netio_dir);
	printf("Sniffing to: %s\n", config.sniff_dir);
	printf("Flush at write: %s\n", (config.flush_at_write ? "yes" : "no"));
	printf("Debug level: %d\n", config.debug_level);
	printf("--------\n");

	while (1) {
		if (SIGNAL_END)
			end_process(&obj);

		if (last_time + CHECK_INTERVAL <= time(NULL)) {
			ret = check_files(&obj);
			if (ret)
				return ret;
			last_time = time(NULL);
		}

		ret = poll(obj.sockets, obj.niou, 1000*CHECK_INTERVAL);
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
