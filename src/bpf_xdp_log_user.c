
/*
 * Copyright (C) Chenyue Zhou (zcy.chenyue.zhou@gmail.com)
 */


#include <bpf_xdp_log_user.h>
#include <bpf_xdp_common_user.h>


static char  *_week[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
static char  *_months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };


static int   log_level = 0;
static char  log_file[256] = "\0";


static log_str_t LOG_MAP[] = {
    {
        .data = "DEBUG", /* '\0' will automatically be added to the end of the string */
        .size = sizeof("DEBUG") - 1
    },
    {
        .data = "INFO",
        .size = sizeof("INFO") - 1
    },
    {
        .data = "WARN",
        .size = sizeof("WARN") - 1
    },
    {
        .data = "ERROR",
        .size = sizeof("ERROR") - 1
    },
    {
        .data = "ALERT",
        .size = sizeof("ALERT") - 1
    },
    {
        .data = "EMERG",
        .size = sizeof("EMERG") - 1
    }
};


/* TODO use buffer to write file, or use aio, or use io_uring */
static void __log(int level, const char *msg, const char *file,
                     const char *func, int line)
{
    FILE      *fp;
    char       time_buf[27];
    int        log_to_stdout = log_file[0] == '\0';
    time_t     t;
    struct tm  tm;

    fp = log_to_stdout ? stdout : fopen(log_file, "a");
    if (!fp) {
        return;
    }

    t = time(NULL);
    if (t == (time_t) -1) {
        return;
    }

    localtime_r(&t, &tm);
    snprintf(time_buf, 27, "%s, %02d %s %4d %02d:%02d:%02d",
             _week[tm.tm_wday],
             tm.tm_mday,
             _months[tm.tm_mon],
             tm.tm_year + 1900,
             tm.tm_hour,
             tm.tm_min,
             tm.tm_sec);

#ifdef DEBUG
    fprintf(fp, "%s %d [%s] %s; [%s:%s:%d]\n", time_buf, getpid(),
                                               LOG_MAP[level].data, msg, file,
                                               func, line);
#else
    fprintf(fp, "%s %d [%s] %s;\n", time_buf, getpid(), LOG_MAP[level].data,
            msg);
#endif

    fflush(fp);

    if (!log_to_stdout) {
        fclose(fp);
    }
}


void _log(int level, const char *file, const char *func, int line,
             const char *fmt, ...)
{
    va_list ap;
    char msg[512];

    if (level < log_level) {
        return;
    }

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    __log(level, msg, file, func, line);
}


void set_log_level(const char *level, size_t len) {
    int i;

    for (i = 0; i <= LOG_EMERG; i++) {
        if (len != LOG_MAP[i].size) {
            continue;
        }

        if (strncasecmp(level, LOG_MAP[i].data, len) == 0) {
            log_level = i;

            return;
        }
    }
}


void set_log_file(const char *path, size_t len) {
    if (len > 256) {
        return;
    }

    snprintf(log_file, len, "%s", path);
}
