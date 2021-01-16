
/*
 * Copyright (C) Chenyue Zhou (zcy.chenyue.zhou@gmail.com)
 */


#include <linux/types.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
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
#include <errno.h>

#include <print_packet.h>


typedef struct {
    void *pos;
} hdr_cursor_t;


typedef struct {
    char  *saddr;
    char  *daddr;
    __u32 source;
    __u32 dest;
} print_data_t;


typedef struct {
    __u32        seq;
    __u32        ack_seq;
    __u16        window;
    __u32        length;
    char        *data;
} print_tcp_data_t;


static inline __u16 read_array_to_u16(const __u8 *p) {
    return p[0] << 8 | p[1];
}


static inline __u32 read_array_to_u32(const __u8 *p) {
    return p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
}


static char *flag2str(__u8 flag) {
    __u8 mask = (__u8) ((1 << 8) - 1);

#if defined(__LITTLE_ENDIAN_BITFIELD)
    switch (mask & flag) {
        case 1:
            return "FIN";
        case 1 << 1:
            return "SYN";
        case 1 << 2:
            return "RST";
        case 1 << 3:
            return "PSH";
        case 1 << 4:
            return "ACK";
        case 1 << 5:
            return "URG";
        case 1 << 6:
            return "ECE";
        case 1 << 7:
            return "CWR";
        case 1 | (1 << 4):
            return "FIN,ACK";
        case (1 << 1) | (1 << 4):
            return "SYN,ACK";
        case (1 << 2) | (1 << 4):
            return "RST,ACK";
        case (1 << 3) | (1 << 4):
            return "PSH,ACK";
        case (1 << 5) | (1 << 4):
            return "URG,ACK";
        case (1 << 6) | (1 << 4):
            return "ECE,ACK";
        case (1 << 7) | (1 << 4):
            return "CWR,ACK";
    }
#elif defined(__BIG_ENDIAN_BITFIELD)
    switch (mask & flag) {
        case 1 << 7:
            return "FIN";
        case 1 << 6:
            return "SYN";
        case 1 << 5:
            return "RST";
        case 1 << 4:
            return "PSH";
        case 1 << 3:
            return "ACK";
        case 1 << 2:
            return "URG";
        case 1 << 1:
            return "ECE";
        case 1:
            return "CWR";
        case (1 << 7) | (1 << 3):
            return "FIN,ACK";
        case (1 << 6) | (1 << 3):
            return "SYN,ACK";
        case (1 << 5) | (1 << 3):
            return "RST,ACK";
        case (1 << 4) | (1 << 3):
            return "PSH,ACK";
        case (1 << 2) | (1 << 3):
            return "URG,ACK";
        case (1 << 1) | (1 << 3):
            return "ECE,ACK";
        case 1 | (1 << 3):
            return "CWR,ACK";
    }
#endif

    return "UNKOWN";
}


static int parse_ethhdr(hdr_cursor_t *nh, struct ethhdr **ethhdr) {
	struct ethhdr *eth  = nh->pos;
	int            size = sizeof(struct ethhdr);

	nh->pos += size;
    *ethhdr  = eth;

	return eth->h_proto; /* network-byte-order */
}


static int parse_iphdr(hdr_cursor_t *nh, struct iphdr **iphdr) {
    struct iphdr *iph  = nh->pos;
    int           size;

    size = iph->ihl * 4;

    nh->pos += size;
    *iphdr   = iph;

    return iph->protocol;
}


/* return tcp header size */
static int parse_tcphdr(hdr_cursor_t *nh, struct tcphdr **tcphdr) {
    struct tcphdr *tcph = nh->pos;
    int            size;

    size = tcph->doff * 4;

    nh->pos += size;
    *tcphdr  = tcph;

    return size;
}


/* return udp data size */
static int parse_udphdr(hdr_cursor_t *nh, struct udphdr **udphdr) {
    struct udphdr *udph = nh->pos;
    int            size;

    size = htons(udph->len) - sizeof(struct udphdr);

    nh->pos += sizeof(struct udphdr);
    *udphdr  = udph;

    return size;
}


static char current_options[42][256] = { "[", };
/* kind (1 byte) | length (1 byte) | payload */
static int tcp_parse_options(struct tcphdr *tcph,
        const unsigned char *options, int length)
{
    __u8 opcode, opsize, optcnt = 1;
    int  n = 0;

    while (length > 0) {
        opcode = *options++;

        switch (opcode) {
            case TCPOPT_EOL:
                /* end of options list */

                goto finish;
            case TCPOPT_NOP:
                /* no operation */
                length--;

                n = snprintf(current_options[optcnt++], 5, "nop,");

                continue;
            default:
                if (length < 2) {
                    /* rest options need at least 2 bytes */

                    goto finish;
                }

                opsize = *options++;
                if (opsize < 2) {
                    /* "silly options" */

                    return optcnt;
                }

                if (opsize > length) {
                    /* don't parse partial options */

                    return optcnt;
                }

                switch (opcode) {
                    case TCPOPT_MSS:
                        /* maximum segment size */
                        if (opsize == TCPOLEN_MSS) {
                            __u16 mss = read_array_to_u16((__u8 *) options);
                            // mss = ntohs(mss); /* be16 to cpu */

                            n = snprintf(current_options[optcnt++], 255,
                                    "MSS %d,", mss);
                        }

                        break;

                    case TCPOPT_WINDOW:
                        if (opsize == TCPOLEN_WINDOW) {
                            __u8 snd_wscale = *(__u8 *) options;

                            if (snd_wscale > TCP_MAX_WSCALE) {
                                snd_wscale = TCP_MAX_WSCALE;
                            }

                            n = snprintf(current_options[optcnt++], 255,
                                    "WSCALE %u,", snd_wscale);
                        }

                        break;

                    case TCPOPT_TIMESTAMP:
                        if (opsize == TCPOLEN_TIMESTAMP) {
                            __u32 tsval = read_array_to_u32((__u8 *) options);
                            __u32 tsecr = read_array_to_u32((__u8 *) (options + 4));
                            // tsval = ntohl(tsval); /* be32 to cpu */
                            // tsecr = ntohl(tsecr);

                            n = snprintf(current_options[optcnt++], 255,
                                         "TS val %u ecr %u,", tsval, tsecr);
                        }

                        break;

                    case TCPOPT_SACK_PERM:
                        if (opsize == TCPOLEN_SACK_PERM /* && sysctl_tcp_sack */)
                        {
                            n = snprintf(current_options[optcnt++], 255,
                                         "SACKOK,");
                        }

                        break;

                    case TCPOPT_SACK:
                        {
                            __u8        tmp_size = opsize - 2;
                            sack_block *block = (sack_block *) options;
                            int         used_size = 0;

                            if (opsize <
                                    TCPOLEN_SACK_BASE + TCPOLEN_SACK_PERBLOCK ||
                               (opsize - TCPOLEN_SACK_BASE) %
                               TCPOLEN_SACK_PERBLOCK)
                            {
                                /* kind:length:BBBBEEEEBBBBEEEE...
                                 * These first two bytes are followed by a list
                                 * of 1–4 blocks being selectively acknowledged,
                                 * specified as 32-bit begin/end pointers.*/

                                break;
                            }

                            n = snprintf(current_options[optcnt++], 255, "SACK");

                            while (tmp_size >= sizeof(sack_block)) {
                                __u32 start =
                                    read_array_to_u32((__u8 *) &block->start_seq);
                                __u32 end   =
                                    read_array_to_u32((__u8 *) &block->end_seq);
                                // start = ntohl(start); /* be32 to cpu */
                                // end   = ntohl(end);

                                used_size += n;
                                tmp_size  -= sizeof(sack_block);

                                n += snprintf(
                                        current_options[optcnt - 1] + used_size,
                                        255 - used_size, " <%u/%u>", start, end);

                                block++;
                            }

                            used_size += n;

                            n += snprintf(
                                    current_options[optcnt - 1] + used_size,
                                    255 - used_size, ",");
                        }

                        break;

                    case TCPOPT_MD5SIG:
                        /* TODO */

                        break;

                    case TCPOPT_FASTOPEN:
                    {
                        __u8 len = opsize - TCPOLEN_FASTOPEN_BASE;
                        char buf[TCP_FASTOPEN_COOKIE_MAX + 1] = "\0";

                        if (len >= TCP_FASTOPEN_COOKIE_MIN &&
                                len <= TCP_FASTOPEN_COOKIE_MAX)
                        {
                            memcpy(buf, options, len);
                        }

                        n = snprintf(current_options[optcnt++], 255,
                                     "FS_COOKIE %s", buf);

                        break;
                    }
                    case TCPOPT_EXP:
                        /* TODO */

                        break;

                    default:
                        break;
                }

            options += (opsize - 2);
            length  -= opsize;
        }

    }

finish:
    if (n >= 1 && current_options[optcnt - 1][n - 1] == ',') {
        current_options[optcnt - 1][n - 1] = '\0';
    }

    snprintf(current_options[optcnt++], 2, "]");

    return optcnt;
}


void print_packet(void *data, size_t size) {
    int              i, type, optcnt, options_length, udp_size;
    __u8            *origin_data = data, flag;
    hdr_cursor_t     nh = { .pos = data };
    struct ethhdr   *eth;
    struct iphdr    *iph;
    struct tcphdr   *tcph;
    struct udphdr   *udph;
    struct in_addr   source_addr, dest_addr;
    print_data_t     pdata = {};
    print_tcp_data_t tdata = {};

    type = parse_ethhdr(&nh, &eth);
    if (type == htons(ETH_P_IP)) {
        if ((type = parse_iphdr(&nh, &iph)) == -1) {
            goto done;
        }
    } else {
        goto done;
    }

    source_addr.s_addr = iph->saddr;
    dest_addr.s_addr   = iph->daddr;

    pdata.saddr = inet_ntoa(source_addr);
    pdata.daddr = inet_ntoa(dest_addr);

    size -= (nh.pos - data);

    switch (type) {
        case IPPROTO_TCP:
            flag = origin_data[(nh.pos - data) +
                offsetof(struct tcphdr, ack_seq) + sizeof(__be32) + sizeof(__u8)];

            parse_tcphdr(&nh, &tcph);

            tdata.window  = ntohs(tcph->window);
            tdata.seq     = ntohl(tcph->seq);
            tdata.ack_seq = ntohl(tcph->ack_seq);
            tdata.data    = nh.pos;

            pdata.source  = ntohs(tcph->source);
            pdata.dest    = ntohs(tcph->dest);

            options_length = tcph->doff * 4 - sizeof(struct tcphdr);

            optcnt = tcp_parse_options(tcph,
                (const unsigned char *) (nh.pos - options_length),
                options_length);

            printf("IP %s.%u > %s.%u, flags [%s], ack %u, seq %u, win %u, "
                   "option_size %d, length %ld ", pdata.saddr, pdata.source,
                   pdata.daddr, pdata.dest, flag2str(flag), tdata.ack_seq,
                   tdata.seq, tdata.window, options_length,
                   size - tcph->doff * 4);

            if (optcnt > 2) {
                for (i = 0; i < optcnt; i++) {
                    printf("%s", current_options[i]);
                }
            }

            printf("\n%s\n", tdata.data);

            break;

        case IPPROTO_UDP:
            udp_size = parse_udphdr(&nh, &udph);

            pdata.source = ntohs(udph->source);
            pdata.dest   = ntohs(udph->dest);

            printf("IP %s.%u > %s.%u, UDP, length %d\n%s\n", pdata.saddr,
                   pdata.source, pdata.daddr, pdata.dest, udp_size,
                   (char *) nh.pos);

            goto done;

        default:
            goto done;
    }

done:
    return;
}
