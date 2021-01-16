
/*
 * Copyright (C) Chenyue Zhou (zcy.chenyue.zhou@gmail.com)
 */


#ifndef PRINT_PACKET_H
#define PRINT_PACKET_H


#ifndef PACKET_SIZE
#define PACKET_SIZE 1500
#endif


#define TCPOPT_NOP		 1	 /* Padding */
#define TCPOPT_EOL		 0	 /* End of options */
#define TCPOPT_MSS		 2	 /* Segment size negotiating */
#define TCPOPT_WINDOW	 3	 /* Window scaling */
#define TCPOPT_SACK_PERM 4   /* SACK Permitted */
#define TCPOPT_SACK      5   /* SACK Block */
#define TCPOPT_TIMESTAMP 8	 /* Better RTT estimations/PAWS */
#define TCPOPT_MD5SIG	 19	 /* MD5 Signature (RFC2385) */
#define TCPOPT_FASTOPEN	 34	 /* Fast open (RFC7413) */
#define TCPOPT_EXP		 254 /* Experimental */

#define TCPOLEN_MSS               4
#define TCPOLEN_WINDOW            3
#define TCPOLEN_SACK_PERM         2
#define TCPOLEN_TIMESTAMP         10
#define TCPOLEN_MD5SIG            18
#define TCPOLEN_FASTOPEN_BASE     2
#define TCPOLEN_EXP_FASTOPEN_BASE 4
#define TCPOLEN_EXP_SMC_BASE      6

/* Maximal number of window scale according to RFC1323 */
#define TCP_FASTOPEN_COOKIE_MIN  4
#define TCP_FASTOPEN_COOKIE_MAX  16
#define TCP_FASTOPEN_COOKIE_SIZE 8

#define TCPOLEN_SACK_BASE     2
#define TCPOLEN_SACK_PERBLOCK 8

#define TCP_MAX_WSCALE 14U

typedef struct {
    __u16 cookie;
    __u16 pkt_size;
    __u8  pkt_data[PACKET_SIZE];
} packet_t;


typedef struct {
    __be32 start_seq;
    __be32 end_seq;
} sack_block;


void print_packet(void *data, size_t size);


#endif /* PRINT_PACKET_H */
