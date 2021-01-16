
/*
 * Copyright (C) Chenyue Zhou (zcy.chenyue.zhou@gmail.com)
 */


#ifndef BPF_XDP_LOG_H
#define BPF_XDP_LOG_H


#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>


#define LEVEL(_) \
    _(DEBUG) _(INFO) _(WARN) _(ERR) _(ALERT) _(EMERG)

enum LOG_LEVEL {
#define MKENUM(name) LOG_##name,
LEVEL(MKENUM)
#undef MKENUM
};


typedef struct {
    char  *data;
    size_t size;
} log_str_t;


#ifdef DEBUG
static inline void _vraise(const char *file, const char *func, int line,
                           const char *fmt, ...)
{
    va_list ap;
    char    msg[4096];

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    fprintf(stderr, "%s [%s:%s:%d]", msg, file, func, line);
    exit(-1);
}


static inline void _raise(const char *file, const char *func, int line,
                          const char *msg) {
    _vraise(file, func, line, msg);
}


#define raise(msg) _raise(__FILE__, __func__, __LINE__, (msg))
#define vraise(fmt, ...) _vraise(__FILE__, __func__, __LINE__, (fmt), \
                                 __VA_ARGS__)
#endif

void _log(int level, const char *file, const char *func, int line,
          const char *fmt, ...);
void set_log_level(const char *level, size_t len);
void set_log_file(const char *path, size_t len);


#define log(level, msg) \
    _log(level, __FILE__, __func__, __LINE__, msg)
#define vlog(level, fmt, ...) \
    _log(level, __FILE__, __func__, __LINE__, fmt, __VA_ARGS__)


#endif /* BPF_XDP_LOG_H */
