#ifndef _MISC_H_
#define _MISC_H_

void debug(int level, const char *format, ...);
void dump_packet(char *buf, int len);
int need_capture_line(char *str_request);

#endif /* _MISC_H_ */
