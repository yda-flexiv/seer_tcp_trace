#include "seer_tcp_trace.h"
#include "vmlinux.h"
#include <bpf/bpf_endian.h> // bpf_ntohs
#include <bpf/bpf_helpers.h>
// #include <linux/if_ether.h> // ETH_P_IP is this header, but its definition is
// already in vmlinux, except for #defines. So we manually define it here

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

unsigned char lookup_protocol(struct xdp_md *ctx) {
    unsigned char protocol;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end) {
        return 0;
    }
    // If it is an IP packet
    if (bpf_ntohs(eth->h_proto) == ETH_P_IP) {
        // protocol of this packet:
        // 1 ICMP
        // 6 TCP
        // 17 UDP
        struct iphdr *iph = data + sizeof(struct ethhdr);
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) < data_end) {
            protocol = iph->protocol;
        }
    }
    return protocol;
}

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct SeerTcpCommandRecord));
} commands SEC(".maps");

SEC("XDP")
int trace19204(struct xdp_md *ctx) {
    unsigned char protocol;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_PASS;
    }
    // If it is an IP packet
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        return XDP_PASS;
    }
    // protocol of this packet:
    // 1 ICMP
    // 6 TCP
    // 17 UDP
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) < data_end) {
        protocol = iph->protocol;
    }
    if (protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }
    // Get port
    struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) +
            sizeof(struct tcphdr) >=
        data_end) {
        return XDP_PASS;
    }
    if (tcph->dest != SEER_PORT_STATUS) {
        return XDP_PASS;
    }
    struct SeerTcpCommandRecord record = {};
    record.cmd = 1; // TODO extract command from tcp body

    return XDP_PASS;
}
