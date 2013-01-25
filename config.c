#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "config.h"

#define VERSION "0.1"

void display_help(char *name)
{
	printf("Usage: %s [-h] [-i <netio_dir>] [-n <NETMAP>] ", name);
	printf("[-s <sniff_dir>]\n");
	puts("");
	puts("Arguments:");
	printf("\t-h: displays this help\n");
	printf("\t-i <netio_dir>: Look for netio sockets in <netio_dir>\n");
	printf("\t\t[default=/tmp/netioXXX] where XXX is current effective UID\n");
	printf("\t-n <NETMAP>: Location of <NETMAP> file [default=./NETMAP]\n");
	printf("\t-s <sniff_dir>: Directory to place sniffs to ");
	printf("[default=/tmp/iousn*]\n");
	puts("");
	printf("Version: %s\n", VERSION);
	printf("Author: Martin Cechvala\n");
};

void parse_arguments(int argc, char * argv[], char * envp[])
{
	char c;

	while ((c = getopt(argc, argv, "hi:n:s:")) != -1) {
		switch (c) {
			case 'h':
				display_help(argv[0]);
				exit(0);
//			case 'i':
//				config.
		}
	}
			

}
