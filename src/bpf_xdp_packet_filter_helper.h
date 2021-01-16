
/*
 * Copyright (C) Chenyue Zhou (zcy.chenyue.zhou@gmail.com)
 */


#ifndef BPF_XDP_PACKET_FILTER_HELPER_H
#define BPF_XDP_PACKET_FILTER_HELPER_H


#include <stddef.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/bpf.h>
#include <linux/udp.h>
#include <linux/tcp.h>


struct hdr_cursor_s {
	void *pos;
};


static __always_inline int parse_ethhdr(struct hdr_cursor_s *nh, void *data_end,
        struct ethhdr **ethhdr)
{
	struct ethhdr *eth  = nh->pos;
	int            size = sizeof(struct ethhdr);

	if ((void *) eth + size > data_end) {
		return -1;
    }

	nh->pos += size;
    *ethhdr  = eth;

	return eth->h_proto; /* network-byte-order */
}


static __always_inline int parse_iphdr(struct hdr_cursor_s *nh, void *data_end,
        struct iphdr **iphdr)
{
    struct iphdr *iph  = nh->pos;
    int           size;

    /* check ihl and version */
    if ((void *) iph + 2 > data_end) {
        return -1;
    }

    size = iph->ihl * 4;
    if(size < sizeof(struct iphdr)) {
        return -1;
    }

    if ((void *) iph + size > data_end) {
        return -1;
    }

    nh->pos += size;
    *iphdr   = iph;

    /* in some kernel version it's necessary to add bond check */
    if ((void *) iph + offsetof(struct iphdr, protocol) + 1 > data_end) {
        return -1;
    }

    return iph->protocol;
}


static __always_inline int parse_ipv6hdr(struct hdr_cursor_s *nh, void *data_end,
        struct ipv6hdr **ipv6hdr)
{
    struct ipv6hdr *ipv6h = nh->pos;
    int             size  = sizeof(struct ipv6hdr);

    if (nh->pos + size > data_end) {
        return -1;
    }

    nh->pos += size;
    *ipv6hdr = ipv6h;

    /* in some kernel version it's necessary to add bond check */
    if ((void *) ipv6h + offsetof(struct ipv6hdr, nexthdr) + 1 > data_end) {
        return -1;
    }

    /* TODO deal with extension headers (routing header, fragment header)... */
    return ipv6h->nexthdr;
}


static __always_inline int parse_udphdr(struct hdr_cursor_s *nh, void *data_end,
        struct udphdr **udphdr)
{
    struct udphdr *udph = nh->pos;
    int            size = sizeof(struct udphdr), len;

    if ((void *) udph + offsetof(struct udphdr, len) > data_end) {
        return -1;
    }

    len = bpf_ntohs(udph->len);
    if (len - size < 0) {
        return -1;
    }

    *udphdr = udph;

    return len;
}


static __always_inline int parse_tcphdr(struct hdr_cursor_s *nh, void *data_end,
        struct tcphdr **tcphdr)
{
    struct tcphdr *tcph = nh->pos;
    int            size;

    if ((void *) tcph + offsetof(struct tcphdr, window)  > data_end) {
        return -1;
    }

    size = tcph->doff * 4;
    if ((void *) tcph + size > data_end) {
        return -1;
    }

    *tcphdr = tcph;

    return size;
}


#endif /* BPF_XDP_PACKET_FILTER_HELPER_H */
