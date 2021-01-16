
/*
 * Copyright (C) Chenyue Zhou (zcy.chenyue.zhou@gmail.com)
 */


#ifndef CONFIG_H
#define CONFIG_H


#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <net/if.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <uapi/linux/if_link.h>


typedef struct {
    __u8    protocol; /* 4 layer */
    __be32  saddr;    /* network order */
    __be32  daddr;
    __be32  addr;
    __be16  source;
    __be16  dest;
    __be16  port;
} custom_rule_t;


typedef struct {
    int   xdp_flags;
    int   ifindex;
    char *ifname;
    char *filename;

    /* bpf */
    int                prog_fd;
    struct bpf_object *obj;

    int  count;
    bool print_timestamp;

    /* packet dump */
    custom_rule_t *rule;
} xdp_config_t;


typedef struct {
    struct option option;
    char         *help;
    char         *metavar;
    int           type;
} option_wrapper_t;


/* option type */
#define OPT_REQURIED 0
#define OPT_OPTIONAL 1
#define OPT_OTHER    2

#define RET_OK    0
#define RET_FAIL -1

#define BUFSIZE 64


void parse_params_to_xdp_config(int argc, char * const *argv,
                                xdp_config_t *config,
                                const option_wrapper_t *long_option_wrapper,
                                const char *doc);


#endif /* CONFIG_H */
