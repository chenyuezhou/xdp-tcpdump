
/*
 * Copyright (C) Chenyue Zhou (zcy.chenyue.zhou@gmail.com)
 */

#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdbool.h>
#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>
#include <linux/types.h>

#include <bpf_xdp_packet_filter_helper.h>


#ifndef MAX_CPUS
#define MAX_CPUS 128
#endif

#ifndef PACKET_SIZE
#define PACKET_SIZE 1500
#endif


#define min(a, b) (a) < (b) ? (a) : (b)


struct packet_meta_s {
    __u16 cookie;
    __u16 pkt_size;
};


/* TODO support ipv6 */
struct custom_rule_s {
    __u8    protocol; /* 4 layer */
    __be32  saddr;    /* network order */
    __be32  daddr;
    __be32  addr;
    __be16  source;
    __be16  dest;
    __be16  port;
};


struct bpf_map_def SEC("maps") my_map = {
    .type        = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size    = sizeof(int),
    .value_size  = sizeof(__u32),
    .max_entries = MAX_CPUS,
};


struct bpf_map_def SEC("maps") rule = {
    .type        = BPF_MAP_TYPE_ARRAY,
    .key_size    = sizeof(int),
    .value_size  = sizeof(struct custom_rule_s),
    .max_entries = 1,
};


static __always_inline void get_rule(struct custom_rule_s *_rule) {
    struct custom_rule_s *ret;
    __u32                 key = 0;

    ret = bpf_map_lookup_elem(&rule, &key);
    if (!ret) {
        bpf_printk("No rule find\n");

        return;
    }

    memcpy(_rule, ret, sizeof(struct custom_rule_s));
}


SEC("xdp_packet_dump")
int xdp_packet_dump_prog(struct xdp_md *ctx) {
    void                 *data_end = (void *) (long) ctx->data_end;
    void                 *data     = (void *) (long) ctx->data;
    __u64                 flags    = BPF_F_CURRENT_CPU;
    struct packet_meta_s  meta;
    __u16                 packet_size;
    int                   ret, type;
    struct hdr_cursor_s   nh = { .pos = data };
    struct ethhdr        *eth;
    struct iphdr         *iph;
    struct tcphdr        *tcph;
    struct udphdr        *udph;
    __be32                saddr;
    __be32                daddr;
    __be16                source;
    __be16                dest;
    struct custom_rule_s  _rule = { 0, 0, 0, 0, 0, 0, 0 };

    if (data < data_end) {
        get_rule(&_rule);

        if (parse_ethhdr(&nh, data_end, &eth) == bpf_htons(ETH_P_IP)) {
            if ((type = parse_iphdr(&nh, data_end, &iph)) == -1) {
                return XDP_ABORTED;
            }

            /* bound check */
            if ((void *) iph + sizeof(struct iphdr) > data_end) {
                return XDP_ABORTED;
            }

            saddr = iph->saddr;
            daddr = iph->daddr;
        } else {
            return XDP_PASS;
        }

        if (type != _rule.protocol && _rule.protocol != 0) {
            return XDP_PASS;
        }

        if (_rule.saddr != saddr && _rule.saddr != 0) {
            return XDP_PASS;
        }

        if (_rule.daddr != daddr && _rule.daddr != 0) {
            return XDP_PASS;
        }

        if (_rule.addr != 0 && _rule.addr != saddr && _rule.addr != daddr) {
            return XDP_PASS;
        }

        switch (_rule.protocol | type) {
            case IPPROTO_TCP:
                if (parse_tcphdr(&nh, data_end, &tcph)) {
                    /* bound check */
                    if ((void *) tcph + sizeof(struct tcphdr) > data_end)
                    {
                        return XDP_ABORTED;
                    }

                    source = tcph->source;
                    dest   = tcph->dest;

                    break;
                }

                return XDP_PASS;

            case IPPROTO_UDP:
                if (parse_udphdr(&nh, data_end, &udph)) {
                    /* bound check */
                    if ((void *) udph + sizeof(struct udphdr) > data_end)
                    {
                        return XDP_ABORTED;
                    }

                    source = udph->source;
                    dest = udph->dest;


                    break;
                }

                return XDP_PASS;

            default:

                return XDP_PASS;
        }

        if (_rule.source != source && _rule.source != 0) {
            return XDP_PASS;
        }

        if (_rule.dest != dest && _rule.dest != 0) {
            return XDP_PASS;
        }

        if (_rule.port != 0 && _rule.port != source && _rule.port != dest) {
            return XDP_PASS;
        }

        meta.cookie   = 0xdead;
        meta.pkt_size = (__u16) (data_end - data);
        packet_size   = min(meta.pkt_size, PACKET_SIZE);

        /* set flags upper 32 bits with the size of the requested sample and the
         * bpf_perf_event_output will attach the specified amount of bytes from
         * packet to the perf event */
        flags |= (__u64) packet_size << 32;
        ret = bpf_perf_event_output(ctx, &my_map, flags, &meta,
                sizeof(struct packet_meta_s));
        if (ret) {
            bpf_printk("bpf_perf_event_output() failed. %d\n", ret);
        }

    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
