#!/usr/bin/env python3

import json
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
try:
    from .utils import format_bytes, ip_to_string, PROTOCOL_NAMES
except ImportError:
    from utils import format_bytes, ip_to_string, PROTOCOL_NAMES
import fcntl
import time
import threading
import tempfile
import shutil
class OutputWriter:
    """Handles output to both JSON and text formats"""
    
    def __init__(self, output_file: str, format_type: str = "auto", debug: bool = False, 
             namespace: Optional[str] = None, interface: Optional[str] = None, 
             flush_after_read: bool = False, thread_id: str = None):  # NEW parameter

        self.output_file = output_file
        self.format_type = format_type
        self.debug = debug
        self._namespace = namespace
        self._interface = interface
        self.flush_after_read = flush_after_read
        self.thread_id = thread_id
        self._lock = threading.RLock()

        # Auto-detect format if not specified
        if format_type == "auto":
            if output_file.endswith('.json'):
                self.format_type = "json"
            else:
                self.format_type = "text"
    
    def write_stats(self, stats_data: List[Dict], timestamp: str, 
                   whitelist_info: Dict) -> bool:
        """Write statistics to output file"""
        try:
            if self.format_type == "json":
                return self._write_json(stats_data, timestamp, whitelist_info)
            else:
                print("Unsupported format type to write provide json file: " + self.format_type)
                return False
        except Exception as e:
            print(f"Error writing to {self.output_file}: {e}")
            return False
    
    
    def _write_json(self, stats_data: List[Dict], timestamp: str, whitelist_info: Dict) -> bool:
        """Thread-safe JSON writing with atomic operations and minimal lock time"""
        
        # Thread safety wrapper
        with getattr(self, '_lock', threading.RLock()):
            try:
                thread_prefix = f"[{getattr(self, 'thread_id', 'main')}]" if self.debug else ""
                if self.debug:
                    print(f"{thread_prefix} 📝 Writing {len(stats_data)} entries to {self.output_file} using thread-safe atomic operations...")
                    if len(stats_data) == 0:
                        print(f"{thread_prefix} ⚠️ No traffic data to write - this may indicate no traffic flowing or eBPF collection issue")
                
                # Generate source ID
                if self._namespace:
                    source_id = f"{self._namespace}--{self._interface}"
                else:
                    source_id = f"host--{self._interface}"
                
                temp_dir = os.path.dirname(self.output_file) or "."
                
                # Ensure output directory exists
                os.makedirs(temp_dir, exist_ok=True)
                
                # Step 1: Quick read with minimal lock time and thread-safe retries
                existing_data = {}
                existing_flows = {}
                read_start = time.time()
                
                if os.path.exists(self.output_file):
                    if self.debug:
                        print(f"{thread_prefix} 📂 Found existing file: {self.output_file}")
                    for attempt in range(5):  # Reduced attempts for thread mode
                        try:
                            with open(self.output_file, 'r') as f:
                                # Thread-aware timeout - shorter for better concurrency
                                try:
                                    fcntl.flock(f.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
                                except (OSError, IOError):
                                    if time.time() - read_start > 0.05:  # 50ms timeout for threads
                                        if self.debug:
                                            print(f"{thread_prefix} 📂 Read timeout, proceeding with partial data")
                                        break
                                    time.sleep(0.005 * (2 ** attempt))  # Exponential backoff 5ms base
                                    continue
                                
                                # Ultra-fast read
                                content = f.read()
                                if content.strip():
                                    existing_data = json.loads(content)
                                    
                                    # Extract existing flows for this specific source only
                                    for source in existing_data.get('sources', []):
                                        if source.get('id') == source_id:
                                            for entry in source.get("traffic_data", []):
                                                flow_key = (entry["source_ip"], entry["destination_ip"], entry["protocol"])
                                                existing_flows[flow_key] = {
                                                    'rx_bytes': entry['rx_bytes'],
                                                    'tx_bytes': entry['tx_bytes'],
                                                    'entry': entry
                                                }
                                            break
                                break
                                
                        except json.JSONDecodeError:
                            existing_data = {}
                            break
                        except Exception as e:
                            if time.time() - read_start > 0.05:  # 50ms total timeout
                                if self.debug:
                                    print(f"{thread_prefix} 📂 Read gave up after timeout: {e}")
                                break
                            time.sleep(0.005 * (2 ** attempt))
                            continue
                else:
                    if self.debug:
                        print(f"{thread_prefix} 📂 No existing file found at: {self.output_file}, will create new file")
                
                # Step 2: Process everything in memory (thread-safe operations)
                if not existing_data:
                    existing_data = {"sources": []}
                elif "sources" not in existing_data:
                    existing_data["sources"] = []
                
                # Find or create source for this thread
                source_index = -1
                for i, source in enumerate(existing_data["sources"]):
                    if source.get("id") == source_id:
                        source_index = i
                        break
                
                if source_index == -1:
                    new_source = {
                        "id": source_id,
                        "metadata": {},
                        "summary": {},
                        "protocol_breakdown": {},
                        "traffic_data": [],
                        "whitelist_info": {}
                    }
                    existing_data["sources"].append(new_source)
                    source_index = len(existing_data["sources"]) - 1
                
                current_source = existing_data["sources"][source_index]
                
                # Process flow updates with thread-aware logging
                updated_flows = {}
                new_flows = 0
                updated_existing_flows = 0

                for entry in stats_data:
                    src_ip_str = ip_to_string(entry['src_ip'])
                    dst_ip_str = ip_to_string(entry['dst_ip'])
                    flow_key = (src_ip_str, dst_ip_str, entry['protocol'])
                    
                    if flow_key in existing_flows:
                        existing_entry = existing_flows[flow_key]
                        if self.flush_after_read:
                            # Incremental mode: add to existing totals
                            new_rx = existing_entry["rx_bytes"] + entry['rx_bytes']
                            new_tx = existing_entry["tx_bytes"] + entry['tx_bytes']
                            if self.debug:
                                print(f"{thread_prefix} 📊 Incremental: {src_ip_str}→{dst_ip_str} +{entry['rx_bytes']}RX +{entry['tx_bytes']}TX")
                        else:
                            # Absolute mode: use current values
                            new_rx = entry['rx_bytes']
                            new_tx = entry['tx_bytes']
                        updated_existing_flows += 1
                    else:
                        # New flow
                        new_rx = entry['rx_bytes']
                        new_tx = entry['tx_bytes']
                        new_flows += 1
                        if self.debug:
                            print(f"{thread_prefix} 📊 New flow: {src_ip_str}→{dst_ip_str} {new_rx}RX {new_tx}TX")
                    
                    updated_flows[flow_key] = {
                        "source_ip": src_ip_str,
                        "destination_ip": dst_ip_str,
                        "protocol": entry['protocol'],
                        "rx_bytes": new_rx,
                        "tx_bytes": new_tx,
                        "total_bytes": new_rx + new_tx,
                        "rx_formatted": format_bytes(new_rx),
                        "tx_formatted": format_bytes(new_tx),
                        "total_formatted": format_bytes(new_rx + new_tx),
                        "last_updated": timestamp
                    }

                # Add unchanged existing flows
                unchanged_flows = 0
                for flow_key, flow_info in existing_flows.items():
                    if flow_key not in updated_flows:
                        updated_flows[flow_key] = flow_info['entry']
                        unchanged_flows += 1
                
                # Calculate summary statistics
                total_rx = sum(entry["rx_bytes"] for entry in updated_flows.values())
                total_tx = sum(entry["tx_bytes"] for entry in updated_flows.values())
                unique_sources = len(set(entry['source_ip'] for entry in updated_flows.values()))
                unique_destinations = len(set(entry['destination_ip'] for entry in updated_flows.values()))
                
                # Calculate protocol breakdown
                protocol_stats = {}
                for entry in updated_flows.values():
                    proto = entry['protocol']
                    if proto not in protocol_stats:
                        protocol_stats[proto] = {"count": 0, "rx_bytes": 0, "tx_bytes": 0}
                    protocol_stats[proto]["count"] += 1
                    protocol_stats[proto]["rx_bytes"] += entry['rx_bytes']
                    protocol_stats[proto]["tx_bytes"] += entry['tx_bytes']
                    protocol_stats[proto]["total_bytes"] = (
                        protocol_stats[proto]["rx_bytes"] + protocol_stats[proto]["tx_bytes"]
                    )
                
                # Update source data with thread metadata
                current_source.update({
                    "metadata": {
                        "timestamp": timestamp,
                        "timestamp_iso": datetime.now().isoformat(),
                        "interface": self._interface,
                        "namespace": self._namespace,
                        "whitelisted_ips_count": whitelist_info.get('count', 0),
                        "total_entries": len(updated_flows),
                        "last_updated": timestamp,
                        "thread_id": getattr(self, 'thread_id', 'main')  # Track which thread wrote this
                    },
                    "summary": {
                        "total_rx_bytes": total_rx,
                        "total_tx_bytes": total_tx,
                        "total_bytes": total_rx + total_tx,
                        "unique_source_ips": unique_sources,
                        "unique_destination_ips": unique_destinations
                    },
                    "protocol_breakdown": protocol_stats,
                    "traffic_data": list(updated_flows.values()),
                    "whitelist_info": whitelist_info
                })
                
                # Step 3: Atomic write using thread-specific temporary file (NO LOCKS)
                try:
                    thread_id = getattr(self, 'thread_id', 'main')
                    with tempfile.NamedTemporaryFile(
                        mode='w', 
                        dir=temp_dir, 
                        prefix=f".{os.path.basename(self.output_file)}.{thread_id}.tmp",
                        suffix='.json',
                        delete=False
                    ) as temp_file:
                        
                        temp_path = temp_file.name
                        json.dump(existing_data, temp_file, indent=2, default=str)
                        temp_file.flush()
                        os.fsync(temp_file.fileno())
                    
                    # Atomic move - instant and thread-safe at OS level
                    shutil.move(temp_path, self.output_file)
                                
                    if self.debug:
                        mode = "FLUSH" if self.flush_after_read else "NO-FLUSH"
                        print(f"{thread_prefix} ✅ JSON atomically updated ({mode}) - {len(updated_flows)} flows")
                        print(f"{thread_prefix} 📊 Changes: {new_flows} new, {updated_existing_flows} updated, {unchanged_flows} unchanged")
                    return True
                    
                except Exception as e:
                    if 'temp_path' in locals() and os.path.exists(temp_path):
                        try:
                            os.unlink(temp_path)
                        except:
                            pass
                    raise e
                    
            except Exception as e:
                thread_prefix = f"[{getattr(self, 'thread_id', 'main')}]" if self.debug else ""
                print(f"{thread_prefix} Error in thread-safe atomic write: {e}")
                if self.debug:
                    import traceback
                    traceback.print_exc()
                return False
    

    def display_new_data_stats(self, stats_data: List[Dict], timestamp: str, whitelist_info: Dict):
        """Display new data collected in this poll cycle"""
        print(f"\n{'='*80}")
        print(f"🆕 NEW Traffic Data This Poll - {timestamp}")  # Make it clear this is NEW
        print(f"Interface: {self._interface}")
        if whitelist_info.get('count', 0) > 0:
            print(f"Whitelisted IPs: {whitelist_info['count']} (excluded from accounting)")
        print(f"{'='*80}")
        
        if not stats_data:
            print("📭 No new traffic data collected in this poll.")
            return
        
        # Print header
        print(f"{'Source IP':<15} {'Dest IP':<15} {'Protocol':<8} {'RX Bytes':<12} {'TX Bytes':<12} {'Total':<12}")
        print("-" * 80)
        
        # Print new statistics
        total_rx = 0
        total_tx = 0
        
        for entry in stats_data:
            src_ip_str = ip_to_string(entry['src_ip'])
            dst_ip_str = ip_to_string(entry['dst_ip'])
            rx_formatted = format_bytes(entry['rx_bytes'])
            tx_formatted = format_bytes(entry['tx_bytes'])
            total_formatted = format_bytes(entry['rx_bytes'] + entry['tx_bytes'])
            
            print(f"{src_ip_str:<15} {dst_ip_str:<15} {entry['protocol']:<8} "
                f"{rx_formatted:<12} {tx_formatted:<12} {total_formatted:<12}")
            
            total_rx += entry['rx_bytes']
            total_tx += entry['tx_bytes']
        
        print("-" * 80)
        print(f"{'🆕 NEW TOTAL':<39} {format_bytes(total_rx):<12} "
            f"{format_bytes(total_tx):<12} {format_bytes(total_rx + total_tx):<12}")
        print()


    def display_console_stats(self, accumulated_data: List[Dict], timestamp: str, whitelist_info: Dict):
        """Display accumulated statistics on console"""
        print(f"\n{'='*80}")
        print(f"📊 CUMULATIVE Network Traffic Statistics - {timestamp}")  # Make it clear this is cumulative
        if whitelist_info.get('count', 0) > 0:
            print(f"Whitelisted IPs: {whitelist_info['count']} (excluded from accounting)")
        print(f"{'='*80}")
        
        if not accumulated_data:
            print("📭 No accumulated traffic data.")
            if whitelist_info.get('count', 0) > 0:
                print("\nNote: Whitelisted IPs are excluded from accounting.")
                sample_ips = whitelist_info.get('sample_ips', [])
                if sample_ips:
                    print(f"Currently whitelisted: {', '.join(sample_ips[:5])}")
            return
        
        # Print header
        print(f"{'Source IP':<15} {'Dest IP':<15} {'Protocol':<8} {'RX Bytes':<12} {'TX Bytes':<12} {'Total':<12}")
        print("-" * 80)
        
        # Print accumulated statistics
        total_rx = 0
        total_tx = 0
        
        for entry in accumulated_data:
            src_ip_str = entry['source_ip']
            dst_ip_str = entry['destination_ip'] 
            rx_formatted = entry['rx_formatted']
            tx_formatted = entry['tx_formatted']
            total_formatted = entry['total_formatted']
            
            print(f"{src_ip_str:<15} {dst_ip_str:<15} {entry['protocol']:<8} "
                f"{rx_formatted:<12} {tx_formatted:<12} {total_formatted:<12}")
            
            total_rx += entry['rx_bytes']
            total_tx += entry['tx_bytes']
        
        print("-" * 80)
        print(f"{'📊 CUMULATIVE TOTAL':<39} {format_bytes(total_rx):<12} "
            f"{format_bytes(total_tx):<12} {format_bytes(total_rx + total_tx):<12}")
        
        # Show sample whitelisted IPs
        sample_ips = whitelist_info.get('sample_ips', [])
        if sample_ips:
            print(f"\nWhitelisted IPs: {', '.join(sample_ips[:5])}")
            if whitelist_info['count'] > 5:
                print(f"... and {whitelist_info['count'] - 5} more")
        
        if self.debug:
            print(f"✓ Statistics written to {self.output_file}")

    def read_accumulated_data(self) -> List[Dict]:
        """Read accumulated data with aggressive retry strategy - never skip accounting"""
        if not os.path.exists(self.output_file):
            return []
        
        # Generate source ID
        if self._namespace:
            source_id = f"{self._namespace}--{self._interface}"
        else:
            source_id = f"host--{self._interface}"
        
        max_retries = 20  # Increased retry count
        base_delay = 0.01  # Start with 10ms
        max_delay = 0.5   # Cap at 500ms
        
        for attempt in range(max_retries):
            try:
                with open(self.output_file, 'r') as f:
                    # Try to acquire shared lock with exponential backoff
                    try:
                        fcntl.flock(f.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
                        
                        # Successfully acquired lock - read data
                        try:
                            json_data = json.load(f)
                            for source in json_data.get("sources", []):
                                if source.get("id") == source_id:
                                    accumulated_data = source.get("traffic_data", [])
                                    if self.debug and attempt > 0:
                                        print(f"📂 Read successful on attempt {attempt + 1}: {len(accumulated_data)} flows")
                                    return accumulated_data
                            
                            # Source not found
                            if self.debug and attempt > 0:
                                print(f"📂 Read successful on attempt {attempt + 1}: source {source_id} not found")
                            return []
                            
                        except json.JSONDecodeError as e:
                            if self.debug:
                                print(f"📂 JSON decode error on attempt {attempt + 1}: {e}")
                            if attempt < max_retries - 1:
                                # Wait and retry for JSON errors too
                                delay = min(base_delay * (2 ** attempt), max_delay)
                                time.sleep(delay)
                                continue
                            return []
                        
                    except (OSError, IOError) as lock_error:
                        # File is locked - implement exponential backoff
                        if attempt < max_retries - 1:
                            # Calculate delay with exponential backoff + jitter
                            delay = min(base_delay * (2 ** attempt), max_delay)
                            # Add small random jitter to avoid thundering herd
                            import random
                            jitter = random.uniform(0, delay * 0.1)
                            final_delay = delay + jitter
                            
                            if self.debug and attempt % 5 == 0:  # Log every 5 attempts
                                print(f"📂 File locked, retry {attempt + 1}/{max_retries} in {final_delay*1000:.1f}ms")
                            
                            time.sleep(final_delay)
                            continue
                        else:
                            # Final attempt failed
                            if self.debug:
                                print(f"📂 File still locked after {max_retries} attempts, but continuing...")
                            # Instead of returning empty, try one final desperate read
                            return self._emergency_read(source_id)
                            
            except FileNotFoundError:
                # File was deleted between existence check and open
                return []
            except Exception as e:
                if attempt < max_retries - 1:
                    # Unexpected error - retry with backoff
                    delay = min(base_delay * (2 ** attempt), max_delay)
                    if self.debug:
                        print(f"📂 Unexpected error on attempt {attempt + 1}: {e}, retrying in {delay*1000:.1f}ms")
                    time.sleep(delay)
                    continue
                else:
                    if self.debug:
                        print(f"📂 Failed after {max_retries} attempts: {e}")
                    return []
        
        # Should never reach here, but return empty as fallback
        return []

    def _emergency_read(self, source_id: str) -> List[Dict]:
        """Emergency read attempt when all retries failed"""
        try:
            if self.debug:
                print(f"🚨 Emergency read attempt for source {source_id}")
            
            # Try to read without any locks as last resort
            with open(self.output_file, 'r') as f:
                # Read content without acquiring any locks
                content = f.read()
                if not content.strip():
                    return []
                
                json_data = json.loads(content)
                for source in json_data.get("sources", []):
                    if source.get("id") == source_id:
                        accumulated_data = source.get("traffic_data", [])
                        if self.debug:
                            print(f"🚨 Emergency read successful: {len(accumulated_data)} flows")
                        return accumulated_data
                
                return []
                
        except Exception as e:
            if self.debug:
                print(f"🚨 Emergency read failed: {e}")
            return []

class OutputFormat:
    """Output format utilities"""
    
    @staticmethod
    def get_namespaced_filename(filename: str, namespace: Optional[str]) -> str:
        """Add namespace prefix to filename"""
        if namespace:
            base, ext = os.path.splitext(filename)
            return f"{base}_{namespace}{ext}"
        return filename