#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

// Fallback includes if vmlinux.h is not complete
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_IPV6  
#define ETH_P_IPV6 0x86DD
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif

#ifndef XDP_PASS
#define XDP_PASS 2
#endif

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

// Map size constants - must match bpf_program.py
#define MAX_ENTRIES 65536
#define MAX_WHITELIST_ENTRIES 1024

// Add this at the top after includes
#ifndef MAP_NAME_SUFFIX
#define MAP_NAME_SUFFIX ""
#endif

#define CONCAT_HELPER(a, b) a ## b
#define CONCAT(a, b) CONCAT_HELPER(a, b)
#define MAP_NAME(base) CONCAT(base, MAP_NAME_SUFFIX)

// Double buffer traffic maps
// Double buffer RX traffic maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct flow_key);
    __type(value, struct traffic_stats);
} t_m_a_r SEC(".maps");  // RX Buffer A

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct flow_key);
    __type(value, struct traffic_stats);
} t_m_b_r SEC(".maps");  // RX Buffer B

// Double buffer TX traffic maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct flow_key);
    __type(value, struct traffic_stats);
} t_m_a_t SEC(".maps");  // TX Buffer A

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct flow_key);
    __type(value, struct traffic_stats);
} t_m_b_t SEC(".maps");  // TX Buffer B

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} a_buf_r SEC(".maps");  // RX active buffer control

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} a_buf_t SEC(".maps");  // TX active buffer control

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_WHITELIST_ENTRIES);
    __type(key, __u32);
    __type(value, struct whitelist_entry);
} w_m_r SEC(".maps");  // RX whitelist map

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_WHITELIST_ENTRIES);
    __type(key, __u32);
    __type(value, struct whitelist_entry);
} w_m_t SEC(".maps");  // TX whitelist map

// Protocol categories - must match bpf_program.py
enum protocol_type {
    PROTO_TCP = 0,
    PROTO_UDP = 1,
    PROTO_ICMP = 2,
    PROTO_UNKNOWN = 3
};

// Ethernet header structure (if not in vmlinux.h)
struct ethhdr_custom {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16 h_proto;
} __attribute__((packed));

// IP header structure (if not in vmlinux.h)
struct iphdr_custom {
    __u8 ihl:4,
         version:4;
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

// Traffic statistics structure - must match bpf_program.py TrafficStats
struct traffic_stats {
    __u64 rx_bytes;
    __u64 tx_bytes;
    __u32 dst_ip;
    __u8 protocol;
    __u8 padding[3];
};

// Whitelist entry structure - must match bpf_program.py WhitelistEntry
struct whitelist_entry {
    __u8 exists;
};

// Map to store whitelisted IP addresses
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_WHITELIST_ENTRIES);
    __type(key, __u32);           // IP address
    __type(value, struct whitelist_entry);
} whitelist_map SEC(".maps");

// Flow key structure for more granular tracking
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u8 protocol;
    __u8 padding[3];
};

// Map to store traffic statistics keyed by flow (src_ip, dst_ip, protocol)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct flow_key);           // Flow tuple
    __type(value, struct traffic_stats);
} traffic_map SEC(".maps");

// Helper function to determine protocol type
static __always_inline enum protocol_type get_protocol_type(__u8 protocol) {
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
// Replace is_ip_whitelisted function:
static __always_inline int is_ip_whitelisted_rx(__u32 ip) {
    struct whitelist_entry *entry = bpf_map_lookup_elem(&w_m_r, &ip);
    return entry != NULL;
}

static __always_inline int is_ip_whitelisted_tx(__u32 ip) {
    struct whitelist_entry *entry = bpf_map_lookup_elem(&w_m_t, &ip);
    return entry != NULL;
}

// Replace get_active_rx_map function:
static __always_inline void* get_active_rx_map() {
    __u32 key = 0;
    __u32 *active_buffer = bpf_map_lookup_elem(&a_buf_r, &key);
    
    if (!active_buffer) {
        return &t_m_a_r;  // Default to buffer A
    }
    
    if (*active_buffer == 0) {
        return &t_m_a_r;  // RX Buffer A
    } else {
        return &t_m_b_r;  // RX Buffer B
    }
}

// Replace get_active_tx_map function:
static __always_inline void* get_active_tx_map() {
    __u32 key = 0;
    __u32 *active_buffer = bpf_map_lookup_elem(&a_buf_t, &key);
    
    if (!active_buffer) {
        return &t_m_a_t;  // Default to buffer A
    }
    
    if (*active_buffer == 0) {
        return &t_m_a_t;  // TX Buffer A
    } else {
        return &t_m_b_t;  // TX Buffer B
    }
}

// Helper function to validate IP header
static __always_inline int validate_ip_header(struct iphdr_custom *ip, void *data_end) {
    // Check basic IP header bounds
    if ((void *)(ip + 1) > data_end)
        return 0;
    
    // Check IP version (must be IPv4)
    if (ip->version != 4)
        return 0;
    
    // Check header length (minimum 20 bytes)
    if (ip->ihl < 5)
        return 0;
    
    // Check if we have the full header based on IHL
    if ((void *)ip + (ip->ihl * 4) > data_end)
        return 0;
    
    return 1;
}

// Helper function to update or create traffic statistics
// Replace existing update_traffic_stats function around line 140

static __always_inline void update_traffic_stats(__u32 src_ip, __u32 dst_ip, 
    __u16 bytes, enum protocol_type proto_type, 
    int is_rx) {
    struct flow_key key = {
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .protocol = proto_type,
        .padding = {0}
    };

    // Get the appropriate active map based on direction
    void *active_map;
    if (is_rx) {
        active_map = get_active_rx_map();
    } else {
        active_map = get_active_tx_map();
    }
    
    if (!active_map) {
        return;
    }

    struct traffic_stats *stats = bpf_map_lookup_elem(active_map, &key);

    if (stats) {
        // Update existing entry
        if (is_rx) {
            __sync_fetch_and_add(&stats->rx_bytes, bytes);
        } else {
            __sync_fetch_and_add(&stats->tx_bytes, bytes);
        }
    } else {
        // Create new entry
        struct traffic_stats new_stats = {
            .rx_bytes = is_rx ? bytes : 0,
            .tx_bytes = is_rx ? 0 : bytes,
            .dst_ip = dst_ip,
            .protocol = proto_type,
            .padding = {0}
        };
        bpf_map_update_elem(active_map, &key, &new_stats, BPF_ANY);
    }
}

// XDP program for ingress traffic (RX) - Default method
SEC("xdp")
int xdp_traffic_accounting(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Check if we have enough data for ethernet header
    struct ethhdr_custom *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    // Only process IPv4 packets
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;
    
    // Validate IP header
    struct iphdr_custom *ip = (struct iphdr_custom *)(eth + 1);
    if (!validate_ip_header(ip, data_end))
        return XDP_PASS;
    
    __u32 src_ip = bpf_ntohl(ip->saddr);
    __u32 dst_ip = bpf_ntohl(ip->daddr);
    __u16 total_len = bpf_ntohs(ip->tot_len);
    
    // Check if source or destination IP is whitelisted
    if (is_ip_whitelisted_rx(src_ip) || is_ip_whitelisted_rx(dst_ip)) {
        return XDP_PASS;  // Skip accounting for whitelisted IPs
    }
    
    enum protocol_type proto_type = get_protocol_type(ip->protocol);
    
    // For XDP (ingress), account traffic to the destination IP (receiving host)
    // This makes more sense from a host accounting perspective
    update_traffic_stats(dst_ip, src_ip, total_len, proto_type, 1);
    
    return XDP_PASS;
}

// Alternative XDP program that accounts by source IP (original behavior)
SEC("xdp")
int xdp_traffic_accounting_by_source(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr_custom *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;
    
    struct iphdr_custom *ip = (struct iphdr_custom *)(eth + 1);
    if (!validate_ip_header(ip, data_end))
        return XDP_PASS;
    
    __u32 src_ip = bpf_ntohl(ip->saddr);
    __u32 dst_ip = bpf_ntohl(ip->daddr);
    __u16 total_len = bpf_ntohs(ip->tot_len);
    
    if (is_ip_whitelisted_rx(src_ip) || is_ip_whitelisted_rx(dst_ip)) {
        return XDP_PASS;
    }
    
    enum protocol_type proto_type = get_protocol_type(ip->protocol);
    
    // Account by source IP (original behavior)
    update_traffic_stats(src_ip, dst_ip, total_len, proto_type, 1);
    
    return XDP_PASS;
}

// TC program for ingress traffic (RX) - Alternative to XDP
SEC("classifier/ingress")
int tc_traffic_in(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    // Check if we have enough data for ethernet header
    struct ethhdr_custom *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    
    // Only process IPv4 packets
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;
    
    // Validate IP header
    struct iphdr_custom *ip = (struct iphdr_custom *)(eth + 1);
    if (!validate_ip_header(ip, data_end))
        return TC_ACT_OK;
    
    __u32 src_ip = bpf_ntohl(ip->saddr);
    __u32 dst_ip = bpf_ntohl(ip->daddr);
    __u16 total_len = bpf_ntohs(ip->tot_len);
    
    // Check if source or destination IP is whitelisted
    if (is_ip_whitelisted_rx(src_ip) || is_ip_whitelisted_rx(dst_ip)) {
        return TC_ACT_OK;  // Skip accounting for whitelisted IPs
    }
    
    enum protocol_type proto_type = get_protocol_type(ip->protocol);
    
    // For TC ingress, account traffic to the destination IP (receiving host)
    // Same behavior as XDP ingress for consistency
    update_traffic_stats(dst_ip, src_ip, total_len, proto_type, 1);
    
    return TC_ACT_OK;
}

// TC program for ingress traffic with source-based accounting (alternative)
SEC("tc")
int tc_traffic_accounting_ingress_by_source(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    struct ethhdr_custom *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;
    
    struct iphdr_custom *ip = (struct iphdr_custom *)(eth + 1);
    if (!validate_ip_header(ip, data_end))
        return TC_ACT_OK;
    
    __u32 src_ip = bpf_ntohl(ip->saddr);
    __u32 dst_ip = bpf_ntohl(ip->daddr);
    __u16 total_len = bpf_ntohs(ip->tot_len);
    
    if (is_ip_whitelisted_rx(src_ip) || is_ip_whitelisted_rx(dst_ip)) {
        return TC_ACT_OK;
    }
    
    enum protocol_type proto_type = get_protocol_type(ip->protocol);
    
    // Account by source IP (original behavior)
    update_traffic_stats(src_ip, dst_ip, total_len, proto_type, 1);
    
    return TC_ACT_OK;
}

// TC program for egress traffic (TX)
SEC("classifier/egress")
int tc_traffic_eg(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    // Check if we have enough data for ethernet header
    struct ethhdr_custom *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    
    // Only process IPv4 packets
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;
    
    // Validate IP header
    struct iphdr_custom *ip = (struct iphdr_custom *)(eth + 1);
    if (!validate_ip_header(ip, data_end))
        return TC_ACT_OK;
    
    __u32 src_ip = bpf_ntohl(ip->saddr);
    __u32 dst_ip = bpf_ntohl(ip->daddr);
    __u16 total_len = bpf_ntohs(ip->tot_len);
    
    // Check if source or destination IP is whitelisted
    if (is_ip_whitelisted_tx(src_ip) || is_ip_whitelisted_tx(dst_ip)) {
        return TC_ACT_OK;  // Skip accounting for whitelisted IPs
    }
    
    enum protocol_type proto_type = get_protocol_type(ip->protocol);
    
    // For TC egress, account by source IP (sending host)
    update_traffic_stats(src_ip, dst_ip, total_len, proto_type, 0);
    
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";