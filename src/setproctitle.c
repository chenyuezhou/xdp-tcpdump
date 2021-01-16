
/*
 * Copyright (C) Chenyue Zhou (zcy.chenyue.zhou@gmail.com)
 */


#include <setproctitle.h>


extern char **environ;

static char *argv_last;
static char *argv_start;


/* argv[] environ[], argv[0] is default process name */
int init_setproctitle(char **argv)
{
    char  *p;
    size_t size;
    int    i;

    size = 0;

    for (i = 0; environ[i]; i++) {
        size += strlen(environ[i]) + 1;
    }

    p = calloc(1, size);
    if (p == NULL) {
        return -1;
    }

    argv_start = argv[0];
    argv_last  = argv[0];

    for (i = 0; argv[i]; i++) {
        if (argv_last == argv[i]) {
            argv_last = argv[i] + strlen(argv[i]) + 1;
        }
    }

    /* copy environ to another address */
    for (i = 0; environ[i]; i++) {
        if (argv_last == environ[i]) {

            size      = strlen(environ[i]) + 1;
            argv_last = environ[i] + size;

            memcpy(p, environ[i], size);
            environ[i] = p;
            p         += size;
        }
    }

    /* end of process name (argv) */
    argv_last--;

    return 0;
}


static char *cpystrn(char *dst, char *src, size_t n) {
    if (n <= 0 ) {
        return dst;
    }

    while (n--) {
        *dst = *src;

        if (*dst == '\0') {
            return dst;
        }

        dst++;
        src++;
    }

    *dst = '\0';

    return dst;
}


void setproctitle(char *title, size_t len) {
    char  *p;

    p = cpystrn(argv_start, title,
            setproctitle_min((size_t) (argv_last - argv_start), len));

    if (argv_last - p) {
        memset(p, '\0', argv_last - p);
    }
}
