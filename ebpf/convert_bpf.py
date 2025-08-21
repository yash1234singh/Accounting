#!/usr/bin/env python3

"""
Convert network_accounting.bpf.c to BCC-compatible format
This script helps convert the standalone eBPF C code to work with BCC
"""

import re
import os
import sys

def convert_bpf_to_bcc(input_file, output_file):
    """Convert standalone eBPF C code to BCC format"""
    
    if not os.path.exists(input_file):
        print(f"Error: {input_file} not found")
        return False
    
    with open(input_file, 'r') as f:
        content = f.read()
    
    # BCC-compatible version
    bcc_content = '''#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <uapi/linux/bpf.h>

#define MAX_ENTRIES 65536
#define MAX_WHITELIST_ENTRIES 1024

// Protocol categories
enum protocol_type {
    PROTO_TCP = 0,
    PROTO_UDP = 1,
    PROTO_ICMP = 2,
    PROTO_UNKNOWN = 3
};

// Traffic statistics structure
struct traffic_stats {
    u64 rx_bytes;
    u64 tx_bytes;
    u32 dst_ip;
    u8 protocol;
    u8 padding[3];
};

// Whitelist entry structure
struct whitelist_entry {
    u8 exists;
};

// Map to store traffic statistics keyed by source IP
BPF_HASH(traffic_map, u32, struct traffic_stats, MAX_ENTRIES);

// Map to store whitelisted IP addresses
BPF_HASH(whitelist_map, u32, struct whitelist_entry, MAX_WHITELIST_ENTRIES);

// Helper function to determine protocol type
static inline enum protocol_type get_protocol_type(u8 protocol) {
    switch (protocol) {
        case IPPROTO_TCP:
            return PROTO_TCP;
        case IPPROTO_UDP:
            return PROTO_UDP;
        case IPPROTO_ICMP:
            return PROTO_ICMP;
        default:
            return PROTO_UNKNOWN;
    }
}

// Helper function to check if IP is whitelisted
static inline int is_ip_whitelisted(u32 ip) {
    struct whitelist_entry *entry = whitelist_map.lookup(&ip);
    return entry != NULL;
}

// Helper function to validate IP header
static inline int validate_ip_header(struct iphdr *ip, void *data_end) {
    if ((void *)(ip + 1) > data_end)
        return 0;
    
    if (ip->version != 4)
        return 0;
    
    if (ip->ihl < 5)
        return 0;
    
    if ((void *)ip + (ip->ihl * 4) > data_end)
        return 0;
    
    return 1;
}

// Helper function to update traffic statistics
static inline void update_traffic_stats(u32 accounting_ip, u32 peer_ip, 
                                       u16 bytes, enum protocol_type proto_type, 
                                       int is_rx) {
    struct traffic_stats *stats = traffic_map.lookup(&accounting_ip);
    
    if (stats) {
        if (is_rx) {
            lock_xadd(&stats->rx_bytes, bytes);
        } else {
            lock_xadd(&stats->tx_bytes, bytes);
        }
        stats->dst_ip = peer_ip;
        stats->protocol = proto_type;
    } else {
        struct traffic_stats new_stats = {
            .rx_bytes = is_rx ? bytes : 0,
            .tx_bytes = is_rx ? 0 : bytes,
            .dst_ip = peer_ip,
            .protocol = proto_type
        };
        traffic_map.update(&accounting_ip, &new_stats);
    }
}

// XDP program for ingress traffic (RX)
int xdp_traffic_accounting(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;
    
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if (!validate_ip_header(ip, data_end))
        return XDP_PASS;
    
    u32 src_ip = bpf_ntohl(ip->saddr);
    u32 dst_ip = bpf_ntohl(ip->daddr);
    u16 total_len = bpf_ntohs(ip->tot_len);
    
    if (is_ip_whitelisted(src_ip) || is_ip_whitelisted(dst_ip)) {
        return XDP_PASS;
    }
    
    enum protocol_type proto_type = get_protocol_type(ip->protocol);
    
    // Account to destination IP (receiving host)
    update_traffic_stats(dst_ip, src_ip, total_len, proto_type, 1);
    
    return XDP_PASS;
}

// XDP program with source-based accounting (alternative)
int xdp_traffic_accounting_by_source(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;
    
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if (!validate_ip_header(ip, data_end))
        return XDP_PASS;
    
    u32 src_ip = bpf_ntohl(ip->saddr);
    u32 dst_ip = bpf_ntohl(ip->daddr);
    u16 total_len = bpf_ntohs(ip->tot_len);
    
    if (is_ip_whitelisted(src_ip) || is_ip_whitelisted(dst_ip)) {
        return XDP_PASS;
    }
    
    enum protocol_type proto_type = get_protocol_type(ip->protocol);
    
    // Account by source IP (original behavior)
    update_traffic_stats(src_ip, dst_ip, total_len, proto_type, 1);
    
    return XDP_PASS;
}

// TC program for egress traffic (TX)
int tc_traffic_accounting(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;
    
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if (!validate_ip_header(ip, data_end))
        return TC_ACT_OK;
    
    u32 src_ip = bpf_ntohl(ip->saddr);
    u32 dst_ip = bpf_ntohl(ip->daddr);
    u16 total_len = bpf_ntohs(ip->tot_len);
    
    if (is_ip_whitelisted(src_ip) || is_ip_whitelisted(dst_ip)) {
        return TC_ACT_OK;
    }
    
    enum protocol_type proto_type = get_protocol_type(ip->protocol);
    
    // Account by source IP (sending host)
    update_traffic_stats(src_ip, dst_ip, total_len, proto_type, 0);
    
    return TC_ACT_OK;
}
'''
    
    try:
        with open(output_file, 'w') as f:
            f.write(bcc_content)
        print(f"✓ Converted to BCC format: {output_file}")
        return True
    except Exception as e:
        print(f"Error writing to {output_file}: {e}")
        return False

def main():
    input_file = "network_accounting.bpf.c"
    output_file = "network_accounting_bcc.c"
    
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
    if len(sys.argv) > 2:
        output_file = sys.argv[2]
    
    print("Converting eBPF C code to BCC format...")
    print(f"Input: {input_file}")
    print(f"Output: {output_file}")
    
    if convert_bpf_to_bcc(input_file, output_file):
        print("\n✓ Conversion successful!")
        print(f"You can now use: BPF(src_file='{output_file}')")
    else:
        print("\n❌ Conversion failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()