#ifndef _CONFIG_H_
#define _CONFIG_H_

struct config_s config;

struct config_s {
	char *socket_dir;
	char *netmap_file;
	char *sniff_dir;
};

void parse_arguments(int argc, char * argv[], char * envp[]);


#endif /* _CONFIG_H_*/
