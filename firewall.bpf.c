// SPDX-License-Identifier: GPL-2.0

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u16 __sum16;
typedef __u32 __wsum;

#ifndef BPF_MAP_TYPE_HASH
#define BPF_MAP_TYPE_HASH 1
#endif
#ifndef BPF_MAP_TYPE_PERF_EVENT_ARRAY
#define BPF_MAP_TYPE_PERF_EVENT_ARRAY 9
#endif
#ifndef BPF_MAP_TYPE_RINGBUF
#define BPF_MAP_TYPE_RINGBUF 27
#endif

#ifndef BPF_F_CURRENT_CPU
#define BPF_F_CURRENT_CPU 0xffffffffULL
#endif

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define XDP_PASS 2
#define XDP_DROP 1

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1

struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16 h_proto;
} __attribute__((packed));

struct iphdr {
    __u8 ihl:4;
    __u8 version:4;
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __sum16 check;
    __be32 saddr;
    __be32 daddr;
} __attribute__((packed));

struct tcphdr {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    __u16 res1:4;
    __u16 doff:4;
    __u16 fin:1;
    __u16 syn:1;
    __u16 rst:1;
    __u16 psh:1;
    __u16 ack:1;
    __u16 urg:1;
    __u16 res2:2;
    __be16 window;
    __sum16 check;
    __be16 urg_ptr;
} __attribute__((packed));

struct udphdr {
    __be16 source;
    __be16 dest;
    __be16 len;
    __sum16 check;
} __attribute__((packed));

struct icmphdr {
    __u8 type;
    __u8 code;
    __sum16 checksum;
    union {
        struct {
            __be16 id;
            __be16 sequence;
        } echo;
        __be32 gateway;
        struct {
            __be16 __unused;
            __be16 mtu;
        } frag;
    } un;
} __attribute__((packed));

struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u16);
    __type(value, __u8);
} allowed_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u8);
} settings SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct event {
    __u16 dest_port;
    __u16 src_port;
    __u8 protocol;
    char reason[32];
};

static __always_inline int is_http(struct tcphdr *tcp, void *data_end) {
    if (tcp->syn || tcp->fin || tcp->rst) return 0;
    if (!tcp->psh) return 0;
    
    char *payload = (char *)(tcp + 1);
    if ((void *)(payload + 8) > data_end) return 0;
    
    if (payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T' && payload[3] == ' ') return 1;
    if (payload[0] == 'P' && payload[1] == 'O' && payload[2] == 'S' && payload[3] == 'T') return 1;
    if (payload[0] == 'H' && payload[1] == 'E' && payload[2] == 'A' && payload[3] == 'D') return 1;
    if (payload[0] == 'P' && payload[1] == 'U' && payload[2] == 'T' && payload[3] == ' ') return 1;
    if (payload[0] == 'D' && payload[1] == 'E' && payload[2] == 'L' && payload[3] == 'E') return 1;
    
    if (payload[0] == 'H' && payload[1] == 'T' && payload[2] == 'T' && payload[3] == 'P') return 1;
    
    return 0;
}

static __always_inline int is_https(struct tcphdr *tcp, void *data_end) {
    if (tcp->syn || tcp->fin || tcp->rst) return 0;
    
    char *payload = (char *)(tcp + 1);
    if ((void *)(payload + 5) > data_end) return 0;
    
    if (payload[0] == 0x16 && payload[1] == 0x03) {
        if (payload[2] >= 0x01 && payload[2] <= 0x04) return 1;
    }
    
    return 0;
}

static __always_inline int is_dns(struct udphdr *udp, void *data_end) {
    char *payload = (char *)(udp + 1);
    if ((void *)(payload + 12) > data_end) return 0;
    
    return 1;
}

static __always_inline void log_blocked(struct xdp_md *ctx, __u16 dest_port, __u16 src_port, __u8 protocol, const char *reason) {
    struct event evt = {
        .dest_port = dest_port,
        .src_port = src_port,
        .protocol = protocol,
    };
    
    for (int i = 0; i < 31 && reason[i] != '\0'; i++) {
        evt.reason[i] = reason[i];
    }
    evt.reason[31] = '\0';
    
    bpf_ringbuf_output(&events, &evt, sizeof(evt), 0);
}

SEC("xdp")
int filter_traffic(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 key_strict = 0;
    __u32 key_allow_dns = 1;
    __u32 key_allow_icmp = 2;
    __u8 *strict_mode = bpf_map_lookup_elem(&settings, &key_strict);
    __u8 *allow_dns = bpf_map_lookup_elem(&settings, &key_allow_dns);
    __u8 *allow_icmp = bpf_map_lookup_elem(&settings, &key_allow_icmp);

    if (ip->protocol == IPPROTO_ICMP) {
        if (allow_icmp) {
            if (*allow_icmp) {
                return XDP_PASS;
            }
        }
        log_blocked(ctx, 0, 0, IPPROTO_ICMP, "NotAllowed");
        return XDP_DROP;
    }

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        __u16 dest_port = bpf_ntohs(tcp->dest);
        __u16 src_port = bpf_ntohs(tcp->source);

        __u8 *allowed = bpf_map_lookup_elem(&allowed_ports, &dest_port);
        if (allowed) {
            goto check_strict;
        }
        
        __u8 *allowed_src = bpf_map_lookup_elem(&allowed_ports, &src_port);
        if (!allowed_src) {
            log_blocked(ctx, dest_port, src_port, IPPROTO_TCP, "NotAllowedPort");
            return XDP_DROP;
        }
        
        check_strict:

        if (strict_mode) {
            if (*strict_mode) {
                if (dest_port == 80 || src_port == 80) {
                    if (!is_http(tcp, data_end)) {
                        log_blocked(ctx, dest_port, src_port, IPPROTO_TCP, "NonHTTPon80");
                        return XDP_DROP;
                    }
                }
                else if (dest_port == 443 || src_port == 443) {
                    if (!is_https(tcp, data_end)) {
                        log_blocked(ctx, dest_port, src_port, IPPROTO_TCP, "NonHTTPSon443");
                        return XDP_DROP;
                    }
                }
            }
        }

        return XDP_PASS;
    }

    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)(ip + 1);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        __u16 dest_port = bpf_ntohs(udp->dest);
        __u16 src_port = bpf_ntohs(udp->source);

        if (allow_dns) {
            if (*allow_dns) {
                if (dest_port == 53 || src_port == 53) {
                    if (is_dns(udp, data_end)) {
                        return XDP_PASS;
                    }
                }
            }
        }

        log_blocked(ctx, dest_port, src_port, IPPROTO_UDP, "NotAllowed");
        return XDP_DROP;
    }

    log_blocked(ctx, 0, 0, 0, "Protocol");
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
