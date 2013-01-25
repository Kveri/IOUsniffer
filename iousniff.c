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
#include <dirent.h>
#include <poll.h>

#define SOCKET_DIR "/tmp/netio0"

int check_files(int **instances, struct pollfd **sockets)
{
	DIR *dir;
	struct dirent *entry;
	int *pi;
	int got_it;
	int len, sock, tmp;
	struct sockaddr_un sock_addr;
	char path_tmp[512];

	dir = opendir(SOCKET_DIR);

	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_type != DT_SOCK)
			continue; // only socket files interest us

		if (strstr(entry->d_name, "_real") != NULL)
			continue; // ignore real sockets

		pi = *instances;
		got_it = 0;
		len = 0;
		while (pi && *pi != 0) {
			// walk instances array, look for current socket
			if (*pi == atoi(entry->d_name))
				got_it = 1;
			pi++;
			len++;
		}

		if (got_it == 1)
			continue; // this socket is already handled

		// this socket isn't handled, add it to instance list
		*instances = (int *)realloc(*instances, sizeof(int) * (len+2));
		(*instances)[len] = atoi(entry->d_name);
		(*instances)[len+1] = 0; // end of array marker

		sock = socket(AF_UNIX, SOCK_DGRAM, 0);
		sock_addr.sun_family = AF_UNIX;
		strcpy(sock_addr.sun_path, SOCKET_DIR);
		strcat(sock_addr.sun_path, "/");
		strcat(sock_addr.sun_path, entry->d_name);
		tmp = strlen(sock_addr.sun_path) + sizeof(sock_addr.sun_family);

		strcpy(path_tmp, sock_addr.sun_path);
		strcat(path_tmp, "_real");
		rename(sock_addr.sun_path, path_tmp);
		bind(sock, (struct sockaddr *)&sock_addr, tmp);

		*sockets = (struct pollfd *)realloc(*sockets,
					sizeof(struct pollfd) * (len+1));
		(*sockets)[len].fd = sock;
		(*sockets)[len].events = POLLIN;
	}

	// count instances
	len = 0;
	pi = *instances;
	while (pi && *pi != 0) {
		pi++;
		len++;
	}

	closedir(dir);

	return len;
}

int main()
{
	unsigned int s;
	struct sockaddr_un remote, dst;
	char buf[65536], path[512];
	int i, j, len, nfds, ret, remote_len;
	int *instances = NULL;
	struct pollfd *sockets = NULL;
	short iou_src, iou_dst, iou_src_if1, iou_src_if2,
		iou_dst_if1, iou_dst_if2;

	while (1) {
		nfds = check_files(&instances, &sockets);

		ret = poll(sockets, nfds, -1);

		if (ret <= 0)
			continue;

		for (i = 0; i < nfds && ret != 0; i++) {
			if (sockets[i].revents != POLLIN)
				continue;

			remote_len = sizeof(remote);
			len = recvfrom(sockets[i].fd, &buf, sizeof(buf), 0,
				(struct sockaddr *)&remote, &remote_len);


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
			sendto(sockets[i].fd, buf, len, 0,
				(struct sockaddr *)&dst, sizeof(dst));

			// dump it
			printf("received from [%s] ", remote.sun_path);
			printf("%d:%d/%d -> %d:%d/%d:\n", iou_src, iou_src_if1,
				iou_src_if2, iou_dst, iou_dst_if1, iou_dst_if2);
			for (j = 0; j < len; j++) {
				printf("%02X ", buf[j] & 0xff);
			}
			printf("\n");

			ret--;
		}
	}
}
