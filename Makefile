all:
	gcc -Wall -O0 -g -ggdb -lpcap -o iousniff iousniff.c
