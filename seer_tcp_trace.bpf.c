#include "seer_tcp_trace.h"
#include "vmlinux.h"
#include <bpf/bpf_endian.h> // bpf_ntohs
#include <bpf/bpf_helpers.h>
// #include <linux/if_ether.h> // ETH_P_IP is this header, but its definition is
// already in vmlinux, except for #defines. So we manually define it here

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#define NOT_A_SEER_COMMAND 0
/**
 * @brief Find out what type of command is this packet.
 */
uint16_t lookup_seer_cmd_type(struct xdp_md *ctx) {
    uint16_t cmd_type = 0;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) >= data_end) {
        goto the_end;
    }
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        goto the_end;
    }
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) >= data_end) {
        goto the_end;
    }
    if (iph->protocol != IPPROTO_TCP) {
        goto the_end;
    }
    // Get port, filter by the destination port
    struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) +
            sizeof(struct tcphdr) >=
        data_end) {
        goto the_end;
    }
    if (tcph->dest !=
        SEER_PORT_STATUS) { // TODO maybe check if the port starts with 192
        goto the_end;
    }
    // Get TCP body, parse seer header
    struct SeerTcpHeader *seerh = data + sizeof(struct ethhdr) +
                                  sizeof(struct iphdr) + sizeof(struct tcphdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) +
            sizeof(struct tcphdr) + sizeof(struct SeerTcpHeader) >=
        data_end) {
        goto the_end;
    }
    if (seerh->m_sync != SEER_TCP_HEADER_MAGIC_BYTE) {
        goto the_end;
    }
    cmd_type = bpf_ntohs(seerh->m_type);

the_end:
    return cmd_type;
}

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(key_size, sizeof(u16));
    __uint(value_size, sizeof(u32));
} commands SEC(".maps");

SEC("XDP")
int trace19204(struct xdp_md *ctx) {
    uint16_t cmd_type = lookup_seer_cmd_type(ctx);
    if (cmd_type == NOT_A_SEER_COMMAND) {
        return XDP_PASS;
    }
    // increment cmd type cnt

    return XDP_PASS;
}
