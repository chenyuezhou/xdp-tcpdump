
/*
 * Copyright (C) Chenyue Zhou (zcy.chenyue.zhou@gmail.com)
 */


#include <bpf.h>
#include <libbpf.h>

#include <bpf_xdp_log_user.h>
#include <bpf_xdp_common_user.h>


#define XDP_UNKNOWN XDP_REDIRECT + 1
static const char *xdp_action_names[XDP_UNKNOWN] = {
 	[XDP_ABORTED]   = "XDP_ABORTED",
	[XDP_DROP]      = "XDP_DROP",
	[XDP_PASS]      = "XDP_PASS",
	[XDP_TX]        = "XDP_TX",
	[XDP_REDIRECT]  = "XDP_REDIRECT",
};


const char *xdp_action2str(int action) {
    if (action < XDP_UNKNOWN && action >= 0) {
        return xdp_action_names[action];
    }

    return NULL;
}


static int xdp_link_attach(int ifindex, int xdp_flags, int prog_fd) {
    int ret, old_flags;

    ret = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
    if (ret == -EEXIST && !(xdp_flags & XDP_FLAGS_UPDATE_IF_NOEXIST)) {

        old_flags  = xdp_flags;
        xdp_flags &= ~XDP_FLAGS_MODES;

        if ((ret = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags)) == 0) {
            /* remove success, set again */
            ret = bpf_set_link_xdp_fd(ifindex, prog_fd, old_flags);
        }
    }

    if (ret < 0) {
        vlog(LOG_ALERT, "bpf_set_link_xdp_fd() failed. %s", strerror(-ret));

        return RET_FAIL;
    }

    return RET_OK;
}


int xdp_link_detach(int ifindex, int xdp_flags, int expected_prog_id) {
    int ret;
    int current_prog_id;

    ret = bpf_get_link_xdp_id(ifindex, &current_prog_id, xdp_flags);
    if (ret) {
        vlog(LOG_ALERT, "bpf_get_link_xdp_id() failed. %s", strerror(-ret));

        return RET_FAIL;
    }

    if (!current_prog_id) {
        vlog(LOG_INFO, "No current ebpf progam on ifindex: %d", ifindex);

        return RET_OK;
    }

    if (expected_prog_id != -1 && current_prog_id != expected_prog_id)
    {
        vlog(LOG_ALERT, "expected_prog_id is %d, but get %d.", expected_prog_id,
             current_prog_id);

        return RET_FAIL;
    }

    if ((ret = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags)) < 0) {
        vlog(LOG_ALERT, "bpf_set_link_xdp_fd() failed. %s", strerror(-ret));

        return RET_FAIL;
    }

    vlog(LOG_INFO, "Removed XDP program id: %d on ifindex: %d",
         current_prog_id, ifindex);

    return RET_OK;
}


static struct bpf_object *_load_bpf_object_file(const char *filename,
                                                int ifindex)
{
    struct bpf_object        *obj;
    int                       ret, prog_fd;
    struct bpf_prog_load_attr prog_load_attr = {
        .prog_type = BPF_PROG_TYPE_XDP,
        .ifindex   = ifindex
    };

    prog_load_attr.file = filename;

    ret = bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd);
    if (ret) {
        vlog(LOG_ALERT, "bpf_prog_load_xattr() failed. %s", strerror(-ret));

        return NULL;
    }

    return obj;
}


int xdp_bpf_load_and_attach(xdp_config_t *config) {
    int                 offload_ifindex = 0;
    struct bpf_program *bpf_prog;

    if (config->xdp_flags & XDP_FLAGS_HW_MODE) {
        /* hardware offload */
        offload_ifindex = config->ifindex;
    }

    /* load object */
    config->obj = _load_bpf_object_file(config->filename, offload_ifindex);

    if (config->obj == NULL) {
        log(LOG_ALERT, "_load_bpf_object_file() failed.");

        return RET_FAIL;
    }

    bpf_prog = bpf_program__next(NULL, config->obj);

    if (bpf_prog == NULL) {
        log(LOG_ALERT, "No vaild program in given bpf-elf");

        return RET_FAIL;
    }

    config->prog_fd = bpf_program__fd(bpf_prog);
    if (config->prog_fd < 0) {
        vlog(LOG_ALERT, "bpf_program__fd() failed. %s",
                        strerror(-(config->prog_fd)));

        return RET_FAIL;
    }

    /* link xdp */
    if (xdp_link_attach(config->ifindex, config->xdp_flags, config->prog_fd)
            == RET_FAIL)
    {
        log(LOG_ALERT, "xdp_link_attach() failed.");

        return RET_FAIL;
    }

    return RET_OK;
}


int xdp_bpf_object_find_map_fd_by_name(struct bpf_object *bpf_obj,
                                       const char mapname[BPF_OBJ_NAME_LEN])
{
    struct bpf_map *map;

    map = bpf_object__find_map_by_name(bpf_obj, mapname);
    if (map == NULL) {
        vlog(LOG_ALERT, "Cannot find map by name: %s", mapname);

        return RET_FAIL;
    }

    return bpf_map__fd(map);
}
