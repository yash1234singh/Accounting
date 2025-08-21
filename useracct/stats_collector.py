#!/usr/bin/env python3

from typing import List, Dict
try:
    from .utils import ip_to_string, PROTOCOL_NAMES
except ImportError:
    from utils import ip_to_string, PROTOCOL_NAMES
import time

class StatsCollector:
    """Handles statistics collection from BPF maps"""
    
    def __init__(self, whitelist_manager, debug: bool = False):
        self.whitelist_manager = whitelist_manager
        self.debug = debug
    
    def collect_stats(self, traffic_map, flush_after_read: bool = True) -> List[Dict]:
        """Collect statistics using double buffer approach with proper bulk clearing"""
        if not traffic_map:
            print("⚠️ Traffic map is None")
            return []
        
        new_stats_data = []
        
        try:
            # Check if this is a double buffer map
            if hasattr(traffic_map, 'switch_and_read_inactive'):
                if self.debug:
                    print("🔄 Using double buffer map - switching and reading")
                
                # Switch buffers and read from inactive buffer
                # The switch_and_read_inactive method should handle bulk clearing internally
                map_items = traffic_map.switch_and_read_inactive(flush_after_read)
                
                if self.debug:
                    print(f"🔍 Read {len(map_items)} entries from inactive buffer")
                    # Show details of first few entries
                    for i, (key_wrapper, stats) in enumerate(map_items[:3]):
                        src_ip = getattr(key_wrapper, 'src_ip', getattr(key_wrapper, 'value', 'unknown'))
                        dst_ip = getattr(key_wrapper, 'dst_ip', getattr(stats, 'dst_ip', 'unknown'))
                        print(f"🔍 Entry {i}: {src_ip} -> {dst_ip}, RX={stats.rx_bytes}, TX={stats.tx_bytes}")
                
                # For double buffer maps, no additional clearing needed - it's handled in switch_and_read_inactive
                            
            else:
                # Fallback to original logic for non-double-buffer maps
                if self.debug:
                    print("🔍 Using single buffer map - reading and clearing")
                
                # For single buffer maps, read all items first
                map_items = list(traffic_map.items())
                
                if self.debug:
                    print(f"🔍 Read {len(map_items)} entries from single buffer map")
                
                # Clear the entire map at once if flush_after_read is True
                if flush_after_read and len(map_items) > 0:
                    try:
                        if hasattr(traffic_map, 'clear'):
                            clear_success = traffic_map.clear()
                            if self.debug:
                                print(f"🧹 Bulk clear result: {clear_success}")
                        else:
                            # Fallback to zero-out method
                            self._zero_out_counters(traffic_map, map_items)
                    except Exception as e:
                        if self.debug:
                            print(f"Warning: Bulk clear failed: {e}")
            
            # Process the collected data (same for both buffer types)
            for key_wrapper, stats in map_items:
                # Skip zero traffic
                if stats.rx_bytes == 0 and stats.tx_bytes == 0:
                    continue
                
                # Parse flow information
                if hasattr(key_wrapper, 'src_ip'):
                    src_ip = key_wrapper.src_ip
                    dst_ip = key_wrapper.dst_ip
                else:
                    src_ip = key_wrapper.value
                    dst_ip = stats.dst_ip
                
                src_ip_str = ip_to_string(src_ip)
                dst_ip_str = ip_to_string(dst_ip)
                
                # Skip whitelisted IPs
                if (self.whitelist_manager.is_whitelisted(src_ip_str) or 
                    self.whitelist_manager.is_whitelisted(dst_ip_str)):
                    continue
                
                new_stats_data.append({
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'rx_bytes': stats.rx_bytes,
                    'tx_bytes': stats.tx_bytes,
                    'protocol': PROTOCOL_NAMES.get(stats.protocol, "UNKNOWN")
                })
            
            if self.debug:
                map_type = "Double buffer" if hasattr(traffic_map, 'switch_and_read_inactive') else "Single buffer"
                print(f"📊 {map_type} collection: {len(new_stats_data)} valid flows")
        
        except Exception as e:
            print(f"Error in collection: {e}")
            if self.debug:
                import traceback
                traceback.print_exc()
        
        return new_stats_data    

    def _zero_out_counters(self, traffic_map, entries):
        """Strategy 1: Zero out RX/TX counters while preserving flow entries"""
        try:
            if self.debug:
                print("🔄 Attempting to zero out traffic counters...")
            
            # Check if this is a DoubleBufferRXTXMapWrapper with _zero_out_buffer_counters method
            if hasattr(traffic_map, '_zero_out_buffer_counters'):
                if self.debug:
                    print("🔍 Using DoubleBufferRXTXMapWrapper._zero_out_buffer_counters() method")
                return traffic_map._zero_out_buffer_counters()
            
            # Handle regular BPF maps (non-double-buffer)
            zeroed_count = 0
            
            for key_wrapper, stats in entries:
                try:
                    # Create new stats with zero counters but preserve other fields
                    if hasattr(stats, '__class__') and hasattr(stats.__class__, '__init__'):
                        try:
                            # Try the expected constructor signature: TrafficStats(rx, tx, dst, proto)
                            zero_stats = stats.__class__(
                                0,  # rx_bytes = 0
                                0,  # tx_bytes = 0
                                getattr(stats, 'dst_ip', 0),  # preserve dst_ip
                                getattr(stats, 'protocol', 0)  # preserve protocol
                            )
                        except TypeError:
                            # Fallback: try to create and set attributes manually
                            zero_stats = stats.__class__()
                            zero_stats.rx_bytes = 0
                            zero_stats.tx_bytes = 0
                            if hasattr(stats, 'dst_ip'):
                                zero_stats.dst_ip = stats.dst_ip
                            if hasattr(stats, 'protocol'):
                                zero_stats.protocol = stats.protocol
                    else:
                        # Create a simple replacement object
                        class ZeroStats:
                            def __init__(self):
                                self.rx_bytes = 0
                                self.tx_bytes = 0
                                self.dst_ip = getattr(stats, 'dst_ip', 0)
                                self.protocol = getattr(stats, 'protocol', 0)
                        zero_stats = ZeroStats()
                    
                    # Check if map supports item assignment
                    if hasattr(traffic_map, '__setitem__'):
                        traffic_map[key_wrapper] = zero_stats
                        zeroed_count += 1
                        
                        if self.debug and zeroed_count <= 3:  # Show first few for debugging
                            if hasattr(key_wrapper, 'src_ip'):
                                print(f"   Zeroed flow: {key_wrapper.src_ip} -> {key_wrapper.dst_ip}")
                            else:
                                print(f"   Zeroed flow: {key_wrapper.value}")
                    else:
                        if self.debug and zeroed_count == 0:  # Show error only once
                            print(f"Warning: {traffic_map.__class__.__name__} does not support item assignment")
                        break  # No point continuing if assignment not supported
                    
                except Exception as e:
                    if self.debug:
                        print(f"Warning: Could not zero out entry: {e}")
                    continue
            
            success = zeroed_count == len(entries)
            if self.debug:
                print(f"✓ Zeroed out {zeroed_count}/{len(entries)} entries in regular map")
            
            return success
            
        except Exception as e:
            if self.debug:
                print(f"Zero-out method failed: {e}")
            return False

    
    def get_whitelist_info(self) -> Dict:
        """Get whitelist information for output"""
        return {
            'enabled': self.whitelist_manager.get_count() > 0,
            'count': self.whitelist_manager.get_count(),
            'sample_ips': self.whitelist_manager.get_sample_ips(10)
        }