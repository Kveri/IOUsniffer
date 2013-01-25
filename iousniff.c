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

		if (strstr(entry->d_name, "_real") != NULL) // ignore real sockets
			continue;

		printf("file: %s\n", entry->d_name);

		pi = *instances;
		got_it = 0;
		len = 0;
		while (pi && *pi != 0) { // walk instances array, look for current socket
			if (*pi == atoi(entry->d_name))
				got_it = 1;

			pi++;
			len++;
		}

		if (got_it == 1) // this socket is already handled
			continue;

		// this socket isn't handled, add it
		printf("len = %d\n", len);
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

		*sockets = (struct pollfd *)realloc(*sockets, sizeof(struct pollfd) * (len+2));
		(*sockets)[len].fd = sock;
		(*sockets)[len].events = POLLIN;
		(*sockets)[len+1].fd = -1;
	}

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
	short iou_src, iou_dst;

	while (1) {
		// zistime zoznam suborov
		nfds = check_files(&instances, &sockets);
		for (i = 0; i < nfds; i++) {
			printf("fd[%d] = %d\n", i, sockets[i].fd);
		}

		ret = poll(sockets, nfds, -1);

		if (ret == 0)
			continue;

		printf("returned FDs = %d\n", ret);

		for (i = 0; i < nfds && ret != 0; i++) {
			if (sockets[i].revents != POLLIN) {
				continue;
			}

			remote_len = sizeof(remote);
			len = recvfrom(sockets[i].fd, &buf, sizeof(buf), 0,
				(struct sockaddr *)&remote, &remote_len);

			printf("received from [%s]:\n", remote.sun_path);
			for (j = 0; j < len; j++) {
				printf("%02X ", buf[j] & 0xff);
			}
			printf("\n");

			iou_dst = ntohs(*((short *)&buf[0]));
			iou_src = ntohs(*((short *)&buf[2]));
			printf("dst IOU: %d\n", iou_dst);
			printf("src IOU: %d\n", iou_src);

			sprintf(path, "%s/%d_real", SOCKET_DIR, iou_dst);
			printf("PATH = %s\n", path);

			dst.sun_family = AF_UNIX;
			strncpy(dst.sun_path, path, sizeof(dst.sun_path)-1);
			sendto(sockets[i].fd, buf, len, 0,
				(struct sockaddr *)&dst, sizeof(dst));
			
			ret--;
		}

		continue;

		len = recv(s, &buf, sizeof(buf), 0);
		printf("received len = %d\n", len);
		for (i = 0; i < len; i++) {
			printf("%x ", buf[i] & 0xff);
		}
		printf("\n\n");
	}
}
