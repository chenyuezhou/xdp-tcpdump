
/*
 * Copyright (C) Chenyue Zhou (zcy.chenyue.zhou@gmail.com)
 */


#include <poll.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <perf-sys.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <linux/perf_event.h>

#include <config.h>
#include <setproctitle.h>
#include <print_packet.h>
#include <bpf_xdp_log_user.h>
#include <bpf_xdp_common_user.h>


#ifndef MAX_CPUS
#define MAX_CPUS 128
#endif


static const char *doc = "XDP tcpdump\n";


option_wrapper_t long_options[] = {
    { { "help", no_argument, NULL, 'h' }, "Show help", NULL, OPT_OPTIONAL },
    { { "version", no_argument, NULL, 'v' }, "Show version", NULL, OPT_OPTIONAL },
    { { "any", no_argument, NULL, 'A' }, "Print each packet", NULL,
        OPT_OPTIONAL },
    { { "timestamp", no_argument, NULL, 't' }, "Print timestamp in every packet",
        NULL, OPT_OPTIONAL },
    { { "interface", required_argument, NULL, 'i' }, "Listen on interface",
        "<ifname>", OPT_REQURIED },
    { { "count", required_argument, NULL, 'c' },
        "Exit after receiving count packets", "<count>", OPT_OPTIONAL },
    { { "tcp", no_argument, NULL, 2 }, "Catch tcp packets", NULL, OPT_OPTIONAL },
    { { "udp", no_argument, NULL, 3 }, "Catch udp packets", NULL, OPT_OPTIONAL },
    { { "port", required_argument, NULL, 4 }, "Specifies port", "<port>",
        OPT_OPTIONAL },
    { { "dst_port", required_argument, NULL, 5 }, "Specifies dest port",
        "<port>", OPT_OPTIONAL },
    { { "src_port", required_argument, NULL, 6 }, "Specifies source port",
        "<port>", OPT_OPTIONAL },
    { { "addr", required_argument, NULL, 7 }, "Specifies addr", "<addr>",
        OPT_OPTIONAL },
    { { "dst_addr", required_argument, NULL, 8 }, "Specifies dest addr",
        "<addr>", OPT_OPTIONAL },
    { { "src_addr", required_argument, NULL, 9 }, "Specifies source addr",
        "<addr>", OPT_OPTIONAL },

    { { "file", required_argument, NULL,  1  }, "Load program from <file>",
        "<filename>", OPT_OTHER },
    { { "drv-mode", no_argument, NULL, 'D' },
        "Install XDP program in DRV mode", NULL, OPT_OTHER },
    { { "hw-mode", no_argument, NULL, 'H' },
        "Install XDP program in HW mode", NULL, OPT_OTHER },

    { { 0, 0, NULL, 0 }, NULL, NULL, 0 }
};


static int pfds[MAX_CPUS];
static struct perf_event_mmap_page *headers[MAX_CPUS];

static int page_size;
static int page_cnt = 8;

static int done  = 0;
static int glb_packet_limit = -1;
static int packet_count = 0;

static bool print_timestamp = false;


static int open_bpf_perf_event(int map_fd, unsigned int num) {
    int                    i;
    struct perf_event_attr attr = {
        /* add time field */
        .sample_type   = PERF_SAMPLE_RAW,
        .type          = PERF_TYPE_SOFTWARE,
        .config        = PERF_COUNT_SW_BPF_OUTPUT,
        .wakeup_events = 1,
    };

    for (i = 0; i < num; i++) {
        /* all processes/threads on the specified CPU. */
        pfds[i] = sys_perf_event_open(&attr, -1, i, -1, 0);

        if (pfds[i] < 0) {
            vlog(LOG_ALERT, "sys_perf_event_open() on cpu %d failed. %s", i,
                    strerror(errno));

            return RET_FAIL;
        }

        if (bpf_map_update_elem(map_fd, &i, &pfds[i], BPF_ANY)) {

            return RET_FAIL;
        }

        ioctl(pfds[i], PERF_EVENT_IOC_ENABLE, 0);
    }

    return RET_OK;
}


static int bpf_event_mmap_header(unsigned int num) {
    int   i, mmap_size;
    void *mmp;

    page_size = getpagesize();
    mmap_size = page_size * (page_cnt + 1);

    for (i = 0; i < num; i++) {
        mmp = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                pfds[i], 0);

        if (mmp == MAP_FAILED) {
            vlog(LOG_ALERT, "mmap bpf event perf header failed. %s",
                    strerror(errno));

            return RET_FAIL;
        }

        headers[i] = mmp;
    }

    return RET_OK;
}


static enum bpf_perf_event_ret _data_output(void *data, size_t size) {
    packet_t      *pk = data;
    struct timeval tv;
    struct tm      tm;

    if (pk->cookie != 0xdead) {
        log(LOG_ALERT, "Cookie error please check bpf program");

        return LIBBPF_PERF_EVENT_ERROR;
    }

    gettimeofday(&tv, NULL);
    if (print_timestamp) {
        printf("%ld.%ld ", tv.tv_sec, tv.tv_usec);
    } else {
        localtime_r(&tv.tv_sec, &tm);

        printf("%02d:%02d:%02d.%ld ", tm.tm_hour, tm.tm_min, tm.tm_sec,
                tv.tv_usec);
    }

    print_packet(pk->pkt_data, pk->pkt_size);

    packet_count++;

    if (glb_packet_limit > 0 && packet_count >= glb_packet_limit) {
        done = 1;
    }

    return LIBBPF_PERF_EVENT_CONT;
}


struct perf_event_sample {
    struct perf_event_header header;
    __u32                    size;
    char                     data[];
};


struct perf_event_lost {
    struct perf_event_header header;
    u64    id;
    u64    lost;
};


typedef enum
bpf_perf_event_ret (*perf_event_print_fn_t)(void *data, size_t size);


static enum bpf_perf_event_ret
_bpf_perf_event_print(struct perf_event_header *hdr, void *private_data)
{
    int                       ret;
    struct perf_event_sample *sample = (struct perf_event_sample *) hdr;
    perf_event_print_fn_t     fn     = private_data;

    if (sample->header.type == PERF_RECORD_SAMPLE) {
        ret = fn(sample->data, sample->size);

        if (ret != LIBBPF_PERF_EVENT_CONT) {
            return ret;
        }

    } else if (sample->header.type == PERF_RECORD_LOST) {
		struct perf_event_lost *lost = (struct perf_event_lost *) hdr;

        vlog(LOG_WARN, "lost %lld events\n", lost->lost);

    } else {
        vlog(LOG_WARN, "Unkown event type %d, size %d\n", sample->header.type,
                sample->header.size);
    }

    return LIBBPF_PERF_EVENT_CONT;
}


static void perf_event_poll(unsigned int num) {
    /* poll() is enough for this */
    int            i, ret;
    size_t         buf_len = 0;
    void          *buf = NULL;
    struct pollfd *fds;

    fds = calloc(num, sizeof(struct pollfd));
    if (!fds) {
        vlog(LOG_ALERT, "calloc(%d, %d) failed. %s", num, sizeof(struct pollfd),
                strerror(errno));

        return;
    }

    for (i = 0; i < num; i++) {
        fds[i].fd     = pfds[i];
        fds[i].events = POLLIN;
    }

    while (!done) {
        poll(fds, num, 1000);

        for (i = 0; i < num; i++) {
            if (!(fds[i].revents & POLLIN)) {
                continue;
            }

            ret = bpf_perf_event_read_simple(headers[i],
                                             page_cnt * page_size,
                                             page_size, &buf, &buf_len,
                                             _bpf_perf_event_print,
                                             _data_output);

            if (ret != LIBBPF_PERF_EVENT_CONT) {
                log(LOG_ALERT, "bpf_perf_event_read_simple() failed.");

                break;
            }
        }
    }

    free(buf);
    free(fds);
}


static void sig_handler(int signo) {
    (void) signo;

    done = 1;
}


static unsigned int get_num_possible_cpus(void)
{
	static const char *fcpu = "/sys/devices/system/cpu/possible";
	unsigned int start, end, possible_cpus = 0;
	char buff[128];
	FILE *fp;
	int n;

	fp = fopen(fcpu, "r");
	if (!fp) {
		printf("Failed to open %s: '%s'!\n", fcpu, strerror(errno));
		exit(1);
	}

	while (fgets(buff, sizeof(buff), fp)) {
		n = sscanf(buff, "%d-%d", &start, &end);
		if (n == 0) {
			printf("Failed to retrieve # possible CPUs!\n");
			exit(1);
		} else if (n == 1) {
			end = start;
		}
		possible_cpus = start == 0 ? end + 1 : 0;
		break;
	}
	fclose(fp);

	return possible_cpus;
}


static int set_rule(int map_fd, xdp_config_t *cfg) {
    int key = 0;

    if (bpf_map_update_elem(map_fd, &key, cfg->rule, BPF_ANY)) {
        vlog(LOG_ALERT, "bpf_map_update_elem(%d) failed. %s", map_fd,
                strerror(errno));

        return RET_FAIL;
    }

    return RET_OK;
}


static void report_result(void) {
    printf("\n%d packets captured\n", packet_count);
}


static void set_xdp_file(char **filename) {
#ifdef XDP_BIN
    if (!access(XDP_BIN, F_OK | R_OK)) {
        *filename = strdup(XDP_BIN);

        return;
    }

#endif

    *filename = strdup("xdp-packet-dump");
}


int main(int argc, char **argv) {
    int                   info_len     = sizeof(struct bpf_prog_info),
                          map_info_len = sizeof(struct bpf_map_info);
    struct bpf_prog_info  info         = {};
    struct bpf_map_info   map_info     = {};
    int                   i, map_fd;
    unsigned int          numcpus;
    xdp_config_t          cfg;

    parse_params_to_xdp_config(argc, argv, &cfg, long_options, doc);

    if (cfg.filename == NULL) {
        set_xdp_file(&cfg.filename);
    }

    glb_packet_limit = cfg.count;
    print_timestamp  = cfg.print_timestamp;

    /* set proc title */
    {
        int    n;
        size_t size, used_size;
        char  *title;
        size = sizeof("xdp-tcpdump:");

        for (i = 0; i < argc; i++) {
            size += strlen(argv[i]) + 1;
        }

        used_size = 0;
        title     = calloc(1, size);

        n = snprintf(title, size - used_size, "xdp-tcpdump:");
        for (i = 0; i < argc; i++) {
            used_size += n;

            if (used_size > size) {
                break;
            }

            n = snprintf(title + used_size, size - used_size, " %s", argv[i]);
        }

        init_setproctitle(argv);
        setproctitle(title, size);
    }

    if (xdp_bpf_load_and_attach(&cfg) == RET_FAIL) {
        log(LOG_ALERT, "xdp_bpf_load_and_attach() failed.");

        return 0;
    }

    if (bpf_obj_get_info_by_fd(cfg.prog_fd, &info, &info_len)) {
        vlog(LOG_ALERT, "bpf_obj_get_info_by_fd(%d) failed. %s", cfg.prog_fd,
                strerror(errno));

        return 0;
    }

    vlog(LOG_INFO, "Success Loading XDP prog name: %s (id: %d) on device: "
            "%s (ifindex: %d)", info.name, info.id, cfg.ifname, cfg.ifindex);

    if ((map_fd = xdp_bpf_object_find_map_fd_by_name(cfg.obj, "rule")) < 0) {
        log(LOG_ALERT, "Can't find rule map.");

        goto finish;
    }

    if (bpf_obj_get_info_by_fd(map_fd, &map_info, &map_info_len)) {
        log(LOG_ALERT, "bpf_obj_get_info_by_fd(map_fd) failed.");

        goto finish;
    }

    vlog(LOG_INFO, "BPF map (bpf_map_type:%d) id:%d name:%s"
                   " key_size:%d value_size:%d max_entries:%d",
                   map_info.type, map_info.id, map_info.name, map_info.key_size,
                   map_info.value_size, map_info.max_entries);

    if (set_rule(map_fd, &cfg) != RET_OK) {
        log(LOG_ALERT, "Set rule failed.");

        goto finish;
    };

    /* find perf map */
    if ((map_fd = xdp_bpf_object_find_map_fd_by_name(cfg.obj, "my_map")) < 0) {
        log(LOG_ALERT, "Can't find perf map.");

        goto finish;
    }

    if (bpf_obj_get_info_by_fd(map_fd, &map_info, &map_info_len)) {
        log(LOG_ALERT, "bpf_obj_get_info_by_fd(map_fd) failed.");

        goto finish;
    }

    vlog(LOG_INFO, "BPF map (bpf_map_type:%d) id:%d name:%s"
                   " key_size:%d value_size:%d max_entries:%d",
                   map_info.type, map_info.id, map_info.name, map_info.key_size,
                   map_info.value_size, map_info.max_entries);

    printf("\n\n");

    if (signal(SIGINT, sig_handler) ||
        signal(SIGHUP, sig_handler) ||
        signal(SIGTERM, sig_handler))
    {
        vlog(LOG_ALERT, "signal() failed. %s", strerror(errno));

        goto finish;
    }

    numcpus = get_num_possible_cpus();

    if (open_bpf_perf_event(map_fd, numcpus) == RET_FAIL) {
        vlog(LOG_ALERT, "open_bpf_perf_event(%d, %d) failed.", map_fd, numcpus);

        goto finish;
    }

    for (i = 0; i < numcpus; i++) {
        if (bpf_event_mmap_header(numcpus) < 0) {
            log(LOG_ALERT, "bpf_event_mmap_header() failed.");

            goto finish;
        }
    }

    perf_event_poll(numcpus);

finish:
    xdp_link_detach(cfg.ifindex, cfg.xdp_flags, -1);

    report_result();

    return 0;
}
