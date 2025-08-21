#!/usr/bin/env python3

"""
Modern eBPF program source code for network accounting
Compatible with BCC dynamic loading - alternative to pre-compiled objects

This file provides the same functionality as network_accounting.bpf.c
but in BCC format for dynamic compilation and loading.

Usage:
    from ebpf.bpf_program import BPFNetworkAccounting
    accounting = BPFNetworkAccounting(interface="eth0", debug=True)
    accounting.attach_programs()
    accounting.start_monitoring()
"""

# Enhanced eBPF program source code matching network_accounting.bpf.c functionality
BPF_PROGRAM = """
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h>

// Map size constants - matching network_accounting.bpf.c
#define MAX_ENTRIES 65536
#define MAX_WHITELIST_ENTRIES 1024
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

#ifndef XDP_PASS
#define XDP_PASS 2
#endif

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

// Protocol categories - must match network_accounting.bpf.c
enum protocol_type {
    PROTO_TCP = 0,
    PROTO_UDP = 1,
    PROTO_ICMP = 2,
    PROTO_UNKNOWN = 3
};

// Flow key structure for granular tracking - matching network_accounting.bpf.c
struct flow_key {
    u32 src_ip;
    u32 dst_ip;
    u8 protocol;
    u8 padding[3];
};

// Traffic statistics structure - must match network_accounting.bpf.c
struct traffic_stats {
    u64 rx_bytes;
    u64 tx_bytes;
    u32 dst_ip;
    u8 protocol;
    u8 padding[3];
};

// Whitelist entry structure - must match network_accounting.bpf.c
struct whitelist_entry {
    u8 exists;
};

// Double buffer RX traffic maps - matching network_accounting.bpf.c
BPF_HASH(traffic_map_a_rx, struct flow_key, struct traffic_stats, MAX_ENTRIES);
BPF_HASH(traffic_map_b_rx, struct flow_key, struct traffic_stats, MAX_ENTRIES);

// Double buffer TX traffic maps - matching network_accounting.bpf.c
BPF_HASH(traffic_map_a_tx, struct flow_key, struct traffic_stats, MAX_ENTRIES);
BPF_HASH(traffic_map_b_tx, struct flow_key, struct traffic_stats, MAX_ENTRIES);

// Active buffer control maps - separate for RX and TX
BPF_ARRAY(active_buffer_rx, u32, 1);
BPF_ARRAY(active_buffer_tx, u32, 1);

// Whitelist maps - separate for RX and TX
BPF_HASH(whitelist_map_rx, u32, struct whitelist_entry, MAX_WHITELIST_ENTRIES);
BPF_HASH(whitelist_map_tx, u32, struct whitelist_entry, MAX_WHITELIST_ENTRIES);

// Legacy single maps for backward compatibility
BPF_HASH(traffic_map, struct flow_key, struct traffic_stats, MAX_ENTRIES);
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

// Helper function to validate IP header
static inline int validate_ip_header(struct iphdr *ip, void *data_end) {
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

// Helper functions to check if IP is whitelisted (separate RX/TX)
static inline int is_ip_whitelisted_rx(u32 ip) {
    struct whitelist_entry *entry = whitelist_map_rx.lookup(&ip);
    return entry != NULL;
}

static inline int is_ip_whitelisted_tx(u32 ip) {
    struct whitelist_entry *entry = whitelist_map_tx.lookup(&ip);
    return entry != NULL;
}

// Helper functions to get active maps
static inline void* get_active_rx_map() {
    u32 key = 0;
    u32 *active_buffer = active_buffer_rx.lookup(&key);
    
    if (!active_buffer || *active_buffer == 0) {
        return &traffic_map_a_rx;  // RX Buffer A
    } else {
        return &traffic_map_b_rx;  // RX Buffer B
    }
}

static inline void* get_active_tx_map() {
    u32 key = 0;
    u32 *active_buffer = active_buffer_tx.lookup(&key);
    
    if (!active_buffer || *active_buffer == 0) {
        return &traffic_map_a_tx;  // TX Buffer A
    } else {
        return &traffic_map_b_tx;  // TX Buffer B
    }
}

// Enhanced traffic statistics update function
static inline void update_traffic_stats(u32 src_ip, u32 dst_ip, 
    u16 bytes, enum protocol_type proto_type, 
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

    // BCC syntax for map lookup with specific map
    struct traffic_stats *stats = NULL;
    if (is_rx) {
        u32 buffer_key = 0;
        u32 *active_buffer = active_buffer_rx.lookup(&buffer_key);
        if (!active_buffer || *active_buffer == 0) {
            stats = traffic_map_a_rx.lookup(&key);
        } else {
            stats = traffic_map_b_rx.lookup(&key);
        }
    } else {
        u32 buffer_key = 0;
        u32 *active_buffer = active_buffer_tx.lookup(&buffer_key);
        if (!active_buffer || *active_buffer == 0) {
            stats = traffic_map_a_tx.lookup(&key);
        } else {
            stats = traffic_map_b_tx.lookup(&key);
        }
    }

    if (stats) {
        // Update existing entry
        if (is_rx) {
            lock_xadd(&stats->rx_bytes, bytes);
        } else {
            lock_xadd(&stats->tx_bytes, bytes);
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
        
        // Update the appropriate map
        if (is_rx) {
            u32 buffer_key = 0;
            u32 *active_buffer = active_buffer_rx.lookup(&buffer_key);
            if (!active_buffer || *active_buffer == 0) {
                traffic_map_a_rx.update(&key, &new_stats);
            } else {
                traffic_map_b_rx.update(&key, &new_stats);
            }
        } else {
            u32 buffer_key = 0;
            u32 *active_buffer = active_buffer_tx.lookup(&buffer_key);
            if (!active_buffer || *active_buffer == 0) {
                traffic_map_a_tx.update(&key, &new_stats);
            } else {
                traffic_map_b_tx.update(&key, &new_stats);
            }
        }
    }
}

// XDP program for ingress traffic (RX) - Enhanced version
int xdp_traffic_accounting(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Check if we have enough data for ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    // Only process IPv4 packets
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;
    
    // Validate IP header
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if (!validate_ip_header(ip, data_end))
        return XDP_PASS;
    
    u32 src_ip = bpf_ntohl(ip->saddr);
    u32 dst_ip = bpf_ntohl(ip->daddr);
    u16 total_len = bpf_ntohs(ip->tot_len);
    
    // Check if source or destination IP is whitelisted
    if (is_ip_whitelisted_rx(src_ip) || is_ip_whitelisted_rx(dst_ip)) {
        return XDP_PASS;  // Skip accounting for whitelisted IPs
    }
    
    enum protocol_type proto_type = get_protocol_type(ip->protocol);
    
    // For XDP (ingress), account traffic to the destination IP (receiving host)
    update_traffic_stats(dst_ip, src_ip, total_len, proto_type, 1);
    
    return XDP_PASS;
}

// Alternative XDP program that accounts by source IP (original behavior)
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
    
    if (is_ip_whitelisted_rx(src_ip) || is_ip_whitelisted_rx(dst_ip)) {
        return XDP_PASS;
    }
    
    enum protocol_type proto_type = get_protocol_type(ip->protocol);
    
    // Account by source IP (original behavior)
    update_traffic_stats(src_ip, dst_ip, total_len, proto_type, 1);
    
    return XDP_PASS;
}

// TC program for ingress traffic (RX) - Alternative to XDP
int tc_traffic_in(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    // Check if we have enough data for ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    
    // Only process IPv4 packets
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;
    
    // Validate IP header
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if (!validate_ip_header(ip, data_end))
        return TC_ACT_OK;
    
    u32 src_ip = bpf_ntohl(ip->saddr);
    u32 dst_ip = bpf_ntohl(ip->daddr);
    u16 total_len = bpf_ntohs(ip->tot_len);
    
    // Check if source or destination IP is whitelisted
    if (is_ip_whitelisted_rx(src_ip) || is_ip_whitelisted_rx(dst_ip)) {
        return TC_ACT_OK;  // Skip accounting for whitelisted IPs
    }
    
    enum protocol_type proto_type = get_protocol_type(ip->protocol);
    
    // For TC ingress, account traffic to the destination IP (receiving host)
    update_traffic_stats(dst_ip, src_ip, total_len, proto_type, 1);
    
    return TC_ACT_OK;
}

// TC program for egress traffic (TX) - Enhanced version
int tc_traffic_eg(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    // Check if we have enough data for ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    
    // Only process IPv4 packets
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;
    
    // Validate IP header
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if (!validate_ip_header(ip, data_end))
        return TC_ACT_OK;
    
    u32 src_ip = bpf_ntohl(ip->saddr);
    u32 dst_ip = bpf_ntohl(ip->daddr);
    u16 total_len = bpf_ntohs(ip->tot_len);
    
    // Check if source or destination IP is whitelisted
    if (is_ip_whitelisted_tx(src_ip) || is_ip_whitelisted_tx(dst_ip)) {
        return TC_ACT_OK;  // Skip accounting for whitelisted IPs
    }
    
    enum protocol_type proto_type = get_protocol_type(ip->protocol);
    
    // For TC egress, account by source IP (sending host)
    update_traffic_stats(src_ip, dst_ip, total_len, proto_type, 0);
    
    return TC_ACT_OK;
}

// Legacy TC program for backward compatibility
int tc_traffic_accounting(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    
    // Only process IPv4 packets
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;
    
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    
    u32 src_ip = bpf_ntohl(ip->saddr);
    u32 dst_ip = bpf_ntohl(ip->daddr);
    u16 total_len = bpf_ntohs(ip->tot_len);
    
    // Use legacy whitelist map
    struct whitelist_entry *src_entry = whitelist_map.lookup(&src_ip);
    struct whitelist_entry *dst_entry = whitelist_map.lookup(&dst_ip);
    if (src_entry != NULL || dst_entry != NULL) {
        return TC_ACT_OK;  // Skip accounting for whitelisted IPs
    }
    
    enum protocol_type proto_type = get_protocol_type(ip->protocol);
    
    // Use legacy single traffic map
    struct flow_key key = {
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .protocol = proto_type,
        .padding = {0}
    };
    
    struct traffic_stats *stats = traffic_map.lookup(&key);
    if (stats) {
        lock_xadd(&stats->tx_bytes, total_len);
        stats->dst_ip = dst_ip;
        stats->protocol = proto_type;
    } else {
        struct traffic_stats new_stats = {
            .rx_bytes = 0,
            .tx_bytes = total_len,
            .dst_ip = dst_ip,
            .protocol = proto_type
        };
        traffic_map.update(&key, &new_stats);
    }
    
    return TC_ACT_OK;
}
"""

# Data structures for BCC
from ctypes import Structure, c_uint32, c_uint64, c_uint8
import os
import sys

class FlowKey(Structure):
    """C structure mapping for flow_key"""
    _fields_ = [
        ("src_ip", c_uint32),
        ("dst_ip", c_uint32),
        ("protocol", c_uint8),
        ("padding", c_uint8 * 3)
    ]

class TrafficStats(Structure):
    """C structure mapping for traffic_stats"""
    _fields_ = [
        ("rx_bytes", c_uint64),
        ("tx_bytes", c_uint64),
        ("dst_ip", c_uint32),
        ("protocol", c_uint8),
        ("padding", c_uint8 * 3)
    ]

class WhitelistEntry(Structure):
    """C structure mapping for whitelist_entry"""
    _fields_ = [
        ("exists", c_uint8)
    ]

class BPFNetworkAccounting:
    """
    Dynamic BPF program loader using BCC
    
    Alternative to pre-compiled object file approach.
    Compiles and loads eBPF programs at runtime.
    
    Usage:
        accounting = BPFNetworkAccounting(interface="eth0", debug=True)
        accounting.attach_programs()
        accounting.start_monitoring()
        accounting.cleanup()
    """
    
    def __init__(self, interface: str, namespace: str = None, use_xdp: bool = False, debug: bool = False):
        self.interface = interface
        self.namespace = namespace
        self.use_xdp = use_xdp
        self.debug = debug
        self.bpf = None
        self.attached = False
        
        # Import BCC here to avoid dependency if not using dynamic loading
        try:
            from bcc import BPF
            self.BPF = BPF
        except ImportError:
            raise ImportError("BCC is required for dynamic eBPF program loading. Install with: pip install bcc")
    
    def load_program(self) -> bool:
        """Load and compile BPF program"""
        try:
            if self.debug:
                print("🔄 Loading BPF program with dynamic compilation...")
            
            # Initialize BPF with our program source
            self.bpf = self.BPF(text=BPF_PROGRAM, debug=0)
            
            if self.debug:
                print("✓ BPF program compiled and loaded successfully")
                print(f"📊 Available maps: {list(self.bpf.get_table_names())}")
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to load BPF program: {e}")
            if self.debug:
                import traceback
                traceback.print_exc()
            return False
    
    def attach_programs(self) -> bool:
        """Attach BPF programs to network interface"""
        if not self.bpf:
            print("❌ BPF program not loaded. Call load_program() first.")
            return False
        
        try:
            if self.use_xdp:
                # XDP mode
                if self.debug:
                    print(f"🔗 Attaching XDP program to {self.interface}...")
                
                xdp_fn = self.bpf.load_func("xdp_traffic_accounting", self.BPF.XDP)
                self.bpf.attach_xdp(self.interface, xdp_fn, 0)
                
                if self.debug:
                    print(f"✓ XDP program attached to {self.interface}")
            
            # Always attach TC egress for complete traffic accounting
            if self.debug:
                print(f"🔗 Attaching TC egress program to {self.interface}...")
            
            tc_egress_fn = self.bpf.load_func("tc_traffic_eg", self.BPF.SCHED_CLS)
            self.bpf.attach_tc_egress(self.interface, tc_egress_fn)
            
            # For TC mode, also attach ingress
            if not self.use_xdp:
                if self.debug:
                    print(f"🔗 Attaching TC ingress program to {self.interface}...")
                
                tc_ingress_fn = self.bpf.load_func("tc_traffic_in", self.BPF.SCHED_CLS)
                self.bpf.attach_tc_ingress(self.interface, tc_ingress_fn)
            
            self.attached = True
            
            if self.debug:
                mode = "XDP + TC egress" if self.use_xdp else "TC ingress + TC egress"
                print(f"✓ Full monitoring active ({mode}) on {self.interface}")
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to attach programs: {e}")
            if self.debug:
                import traceback
                traceback.print_exc()
            return False
    
    def get_maps(self):
        """Get BPF map references for data collection"""
        if not self.bpf:
            return None, None
        
        try:
            # For simple usage, return the double-buffer RX A map and RX whitelist
            traffic_map = self.bpf.get_table("traffic_map_a_rx")
            whitelist_map = self.bpf.get_table("whitelist_map_rx")
            
            return traffic_map, whitelist_map
            
        except Exception as e:
            if self.debug:
                print(f"❌ Error getting maps: {e}")
            return None, None
    
    def get_all_maps(self):
        """Get all BPF maps for advanced usage"""
        if not self.bpf:
            return {}
        
        maps = {}
        map_names = [
            "traffic_map_a_rx", "traffic_map_b_rx",
            "traffic_map_a_tx", "traffic_map_b_tx",
            "active_buffer_rx", "active_buffer_tx",
            "whitelist_map_rx", "whitelist_map_tx",
            "traffic_map", "whitelist_map"  # Legacy maps
        ]
        
        for map_name in map_names:
            try:
                maps[map_name] = self.bpf.get_table(map_name)
            except Exception:
                if self.debug:
                    print(f"⚠️ Map {map_name} not found (may be normal)")
        
        return maps
    
    def populate_whitelist(self, ip_list: list):
        """Populate whitelist maps with IP addresses"""
        if not self.bpf:
            print("❌ BPF program not loaded")
            return False
        
        try:
            whitelist_rx = self.bpf.get_table("whitelist_map_rx")
            whitelist_tx = self.bpf.get_table("whitelist_map_tx")
            
            entry = WhitelistEntry(exists=1)
            
            for ip_str in ip_list:
                import ipaddress
                ip_int = int(ipaddress.IPv4Address(ip_str))
                
                whitelist_rx[c_uint32(ip_int)] = entry
                whitelist_tx[c_uint32(ip_int)] = entry
            
            if self.debug:
                print(f"✓ Populated whitelist with {len(ip_list)} IPs")
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to populate whitelist: {e}")
            return False
    
    def start_monitoring(self, duration: int = None):
        """Start monitoring and display traffic (simple example)"""
        if not self.attached:
            print("❌ Programs not attached. Call attach_programs() first.")
            return
        
        try:
            import time
            
            print(f"🚀 Starting traffic monitoring on {self.interface}")
            print("Press Ctrl+C to stop...")
            
            traffic_map, _ = self.get_maps()
            if not traffic_map:
                print("❌ Could not access traffic map")
                return
            
            start_time = time.time()
            
            while True:
                time.sleep(5)  # Collect every 5 seconds
                
                current_time = time.time()
                if duration and (current_time - start_time) >= duration:
                    break
                
                # Simple traffic display
                print(f"\n📊 Traffic at {time.strftime('%H:%M:%S')}:")
                entry_count = 0
                
                for key, stats in traffic_map.items():
                    import ipaddress
                    src_ip = str(ipaddress.IPv4Address(key.src_ip))
                    dst_ip = str(ipaddress.IPv4Address(key.dst_ip))
                    
                    if stats.rx_bytes > 0 or stats.tx_bytes > 0:
                        print(f"  {src_ip} -> {dst_ip}: RX={stats.rx_bytes}B, TX={stats.tx_bytes}B")
                        entry_count += 1
                
                if entry_count == 0:
                    print("  No traffic recorded")
                else:
                    print(f"  Total flows: {entry_count}")
        
        except KeyboardInterrupt:
            print("\n🛑 Monitoring stopped by user")
        except Exception as e:
            print(f"❌ Error during monitoring: {e}")
            if self.debug:
                import traceback
                traceback.print_exc()
    
    def cleanup(self):
        """Cleanup and detach programs"""
        if self.bpf and self.attached:
            try:
                if self.debug:
                    print(f"🧹 Cleaning up BPF programs on {self.interface}...")
                
                if self.use_xdp:
                    self.bpf.remove_xdp(self.interface, 0)
                    if self.debug:
                        print(f"✓ Removed XDP program from {self.interface}")
                
                # BCC automatically handles TC cleanup when object is destroyed
                
                self.attached = False
                
                if self.debug:
                    print("✓ Cleanup completed")
                    
            except Exception as e:
                print(f"⚠️ Cleanup error: {e}")
        
        self.bpf = None

# Convenience function for quick usage
def create_dynamic_accounting(interface: str, use_xdp: bool = False, debug: bool = False):
    """
    Quick setup function for dynamic BPF loading
    
    Example:
        accounting = create_dynamic_accounting("eth0", use_xdp=True, debug=True)
        accounting.attach_programs()
        accounting.populate_whitelist(["127.0.0.1", "10.0.0.1"])
        accounting.start_monitoring(duration=60)  # Monitor for 60 seconds
        accounting.cleanup()
    """
    return BPFNetworkAccounting(interface=interface, use_xdp=use_xdp, debug=debug)

# Example usage
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 bpf_program.py <interface> [--xdp] [--debug]")
        print("Example: python3 bpf_program.py eth0 --xdp --debug")
        sys.exit(1)
    
    interface = sys.argv[1]
    use_xdp = "--xdp" in sys.argv
    debug = "--debug" in sys.argv
    
    accounting = create_dynamic_accounting(interface, use_xdp=use_xdp, debug=debug)
    
    if not accounting.load_program():
        sys.exit(1)
    
    if not accounting.attach_programs():
        sys.exit(1)
    
    # Example whitelist
    accounting.populate_whitelist(["127.0.0.1", "10.0.0.1"])
    
    try:
        accounting.start_monitoring()
    finally:
        accounting.cleanup()