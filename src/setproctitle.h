
/*
 * Copyright (C) Chenyue Zhou (zcy.chenyue.zhou@gmail.com)
 */


#ifndef SETPROCTITLE_H
#define SETPROCTITLE_H


#include <stdlib.h>
#include <string.h>


#define setproctitle_min(a, b) (a) < (b) ? (a) : (b)


int init_setproctitle(char **argv);
void setproctitle(char *title, size_t title_len);


#endif /* SETPROCTITLE_H */
