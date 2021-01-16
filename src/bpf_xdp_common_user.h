
/*
 * Copyright (C) Chenyue Zhou (zcy.chenyue.zhou@gmail.com)
 */


#ifndef BPF_XDP_COMMON_H
#define BPF_XDP_COMMON_H


#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <errno.h>
#include <bpf.h>
#include <fcntl.h>
#include <libbpf.h>
#include <linux/err.h>

#include <config.h>


/* #define BPF_OBJ_NAME_LEN 16 */

const char *xdp_action2str(int action);

int xdp_link_detach(int ifindex, int xdp_flags, int expected_prog_id);
int xdp_bpf_load_and_attach(xdp_config_t *config);
int xdp_bpf_object_find_map_fd_by_name(struct bpf_object *bpf_obj,
                                       const char mapname[BPF_OBJ_NAME_LEN]);


#endif /* BPF_XDP_COMMON_H */
