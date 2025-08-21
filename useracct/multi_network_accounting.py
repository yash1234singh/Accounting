#!/usr/bin/env python3

"""
Multi-Instance Network Accounting Manager
Manages multiple network accounting instances from a JSON configuration file
with centralized control, monitoring, and summary reporting.
"""
import json
import os
import sys
import time
import signal
import subprocess
import threading  # Add this line
from datetime import datetime
from typing import Dict, List, Optional, Any
import argparse
from concurrent.futures import ThreadPoolExecutor
import fcntl
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed
import copy

class MultiNetworkAccountingManager:
    """Manages multiple network accounting instances"""
    
    def __init__(self, config_file: str, debug: bool = False):
        self.config_file = config_file
        self.debug = debug
        self.instances = {}  # Store instance processes
        self.config = {}
        self.running = False
        self.summary_files = set()  # Track unique summary files
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        if debug:
            print(f"🐛 Manager debug mode enabled - individual instance debug output will be shown")
        else:
            print(f"ℹ️ Manager debug mode disabled - individual instance output will be suppressed")
            print(f"   Note: Individual instance 'debug' settings in config are ignored unless manager --debug is used")
    
    def load_config(self) -> bool:
        """Load configuration from JSON file"""
        try:
            if not os.path.exists(self.config_file):
                print(f"❌ Configuration file not found: {self.config_file}")
                return False
            
            with open(self.config_file, 'r') as f:
                self.config = json.load(f)
            
            if "instances" not in self.config:
                print("❌ Configuration must contain 'instances' array")
                return False
            
            # Collect unique summary files with proper path resolution
            script_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(script_dir)
            
            for instance in self.config["instances"]:
                raw_output_file = instance.get("summary_file", instance.get("output_file"))
                if raw_output_file:
                    # Apply same path resolution as NetworkAccountingModule
                    if not os.path.isabs(raw_output_file):
                        if raw_output_file.startswith(('logs/', 'config/', 'ebpf/')):
                            resolved_file = os.path.join(project_root, raw_output_file)
                        else:
                            # Assume it's in logs folder
                            resolved_file = os.path.join(project_root, "logs", raw_output_file)
                    else:
                        resolved_file = raw_output_file
                    
                    self.summary_files.add(resolved_file)
            
            print(f"✓ Loaded configuration with {len(self.config['instances'])} instances")
            if self.debug:
                print(f"📊 Summary files to monitor: {list(self.summary_files)}")
            
            return True
            
        except json.JSONDecodeError as e:
            print(f"❌ Invalid JSON in configuration file: {e}")
            return False
        except Exception as e:
            print(f"❌ Error loading configuration: {e}")
            return False
    
    def validate_instance_config(self, instance: Dict) -> bool:
        """Validate individual instance configuration"""
        required_fields = ["tag", "interface", "output_file"]
        
        for field in required_fields:
            if field not in instance:
                print(f"❌ Instance missing required field: {field}")
                return False
        
        # Validate interface exists
        interface = instance["interface"]
        namespace = instance.get("namespace")
        
        try:
            if namespace:
                cmd = ["ip", "netns", "exec", namespace, "ip", "link", "show", interface]
            else:
                cmd = ["ip", "link", "show", interface]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"❌ Interface '{interface}' not found in namespace '{namespace or 'host'}'")
                return False
        except Exception as e:
            print(f"❌ Error validating interface {interface}: {e}")
            return False
        
        return True
    
    def start_instance(self, instance_config: Dict) -> Optional[threading.Thread]:
        """Start a single network accounting instance as a thread"""
        try:
            tag = instance_config["tag"]
            
            if not self.validate_instance_config(instance_config):
                return None
            
            # Create a thread-safe queue for this instance
            instance_queue = queue.Queue()
            
            # Create instance-specific stop event
            stop_event = threading.Event()
            
            # Create the thread
            instance_thread = threading.Thread(
                target=self._run_instance_thread,
                args=(instance_config, instance_queue, stop_event),
                name=f"NetworkAccounting-{tag}",
                daemon=False
            )
            
            print(f"✓ Created thread for instance '{tag}'")
            return {
                'thread': instance_thread,
                'queue': instance_queue,
                'stop_event': stop_event,
                'config': instance_config,
                'start_time': datetime.now()
            }
            
        except Exception as e:
            print(f"❌ Error creating thread for instance '{tag}': {e}")
            if self.debug:
                import traceback
                traceback.print_exc()
            return None

    def _run_instance_thread(self, instance_config: Dict, instance_queue: queue.Queue, stop_event: threading.Event):
        """Run a network accounting instance in a thread"""
        tag = instance_config["tag"]
        
        try:
            # Import here to avoid circular imports in thread
            try:
                from .network_accounting import NetworkAccountingModule
            except ImportError:
                from network_accounting import NetworkAccountingModule
            
            # Create the instance
            interface = instance_config["interface"]
            namespace = instance_config.get("namespace")
            raw_output_file = instance_config["output_file"]
            raw_whitelist_file = instance_config.get("whitelist_file")
            
            # Get project root for path resolution
            script_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(script_dir)
            
            # Resolve output file path
            if not os.path.isabs(raw_output_file):
                if raw_output_file.startswith(('logs/', 'config/', 'ebpf/')):
                    output_file = os.path.join(project_root, raw_output_file)
                else:
                    output_file = os.path.join(project_root, "logs", raw_output_file)
            else:
                output_file = raw_output_file
            
            # Resolve whitelist file path
            if raw_whitelist_file:
                if not os.path.isabs(raw_whitelist_file):
                    if raw_whitelist_file.startswith(('logs/', 'config/', 'ebpf/')):
                        whitelist_file = os.path.join(project_root, raw_whitelist_file)
                    else:
                        whitelist_file = os.path.join(project_root, "config", raw_whitelist_file)
                else:
                    whitelist_file = raw_whitelist_file
            else:
                whitelist_file = os.path.join(project_root, "config", "whitelist.json")
            debug = self.debug  # Use manager's debug setting
            
            # Get XDP configuration from instance config
            use_xdp = instance_config.get("xdp", False)
            use_tc_ingress = not use_xdp  # Use TC ingress if XDP is disabled
            
            # DEBUG: Show what we're about to pass
            if debug:
                xdp_mode = "XDP" if use_xdp else "TC"
                print(f"[{tag}] 🐛 Creating NetworkAccountingModule with thread_mode=True, mode={xdp_mode}")
            
            # Create the monitor instance
            monitor = NetworkAccountingModule(
                interface=interface,
                output_file=output_file,
                whitelist_file=whitelist_file,
                namespace=namespace,
                use_tc_ingress=use_tc_ingress,
                debug=debug,
                tag=tag,
                flush_after_read=True,
                thread_mode=True  # Make sure this is explicitly True
            )
            
            if self.debug:
                print(f"[{tag}] 🚀 Starting BPF program loading...")
            
            # Load BPF program
            if not monitor.load_bpf_program():
                print(f"[{tag}] ❌ Failed to load BPF program")
                return
            
            if self.debug:
                print(f"[{tag}] ✓ BPF program loaded successfully")
            
            # Register cleanup handler for this thread
            import atexit
            atexit.register(lambda: monitor.cleanup())
            
            # Run monitoring loop with stop event
            self._run_threaded_monitoring(monitor, stop_event, tag)
            
        except Exception as e:
            print(f"[{tag}] ❌ Thread error: {e}")
            if self.debug:
                import traceback
                traceback.print_exc()
        finally:
            # Cleanup
            try:
                if 'monitor' in locals():
                    monitor.cleanup()
                if self.debug:
                    print(f"[{tag}] 🧹 Thread cleanup completed")
            except Exception as e:
                print(f"[{tag}] Warning: Cleanup error: {e}")

    def _run_threaded_monitoring(self, monitor, stop_event: threading.Event, tag: str):
        """Run monitoring loop with thread stop event"""
        if self.debug:
            print(f"[{tag}] 🚀 Starting threaded monitoring loop...")
        
        iteration = 0
        last_health_check = 0
        
        try:
            # Get maps references once at startup
            traffic_map, whitelist_map = monitor.bpf_manager.get_maps()
            
            if traffic_map is None or whitelist_map is None:
                print(f"[{tag}] ❌ BPF maps not properly initialized")
                return
            
            while not stop_event.is_set():
                try:
                    # Health check every 20 iterations (100 seconds)
                    if iteration - last_health_check >= 20:
                        if not monitor._check_program_health():
                            print(f"[{tag}] ⚠️ Program health check failed, attempting recovery...")
                            if not monitor._recover_programs():
                                print(f"[{tag}] ❌ Program recovery failed, stopping thread...")
                                break
                        last_health_check = iteration

                    # Reload whitelist if changed (every 10 iterations)
                    if iteration % 10 == 0:
                        monitor.whitelist_manager.reload_if_changed(whitelist_map)

                    # Collect stats data
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    stats_data = monitor.stats_collector.collect_stats(traffic_map, flush_after_read=monitor.flush_after_read)
                    whitelist_info = monitor.stats_collector.get_whitelist_info()

                    # ALWAYS write to instance-specific file
                    write_success = monitor.output_writer.write_stats(
                        stats_data, timestamp, whitelist_info
                    )

                    # Display output only in debug mode for threads
                    if self.debug and stats_data:
                        monitor.output_writer.display_new_data_stats(
                            stats_data, timestamp, whitelist_info
                        )
                    elif stats_data:
                        if self.debug:
                            print(f"[{tag}] 🔄 {timestamp}: Collected {len(stats_data)} flows")
                    
                    # Check for stop event with timeout
                    if stop_event.wait(timeout=5.0):
                        break
                        
                    iteration += 1
                    
                except Exception as e:
                    if not stop_event.is_set():
                        print(f"[{tag}] Error in monitoring loop: {e}")
                        if self.debug:
                            import traceback
                            traceback.print_exc()
                        # Wait before retry
                        if stop_event.wait(timeout=5.0):
                            break
                    
        except Exception as e:
            print(f"[{tag}] ❌ Fatal error in threaded monitoring: {e}")
            if self.debug:
                import traceback
                traceback.print_exc()
        
        if self.debug:
            print(f"[{tag}] 🛑 Threaded monitoring stopped")
    
    def start_all_instances(self) -> bool:
        """Start all configured instances as threads"""
        if not self.config.get("instances"):
            print("❌ No instances configured")
            return False
        
        print(f"🚀 Starting {len(self.config['instances'])} network accounting threads...")
        
        success_count = 0
        for instance_config in self.config["instances"]:
            tag = instance_config.get("tag", "unknown")
            
            instance_data = self.start_instance(instance_config)
            if instance_data:
                # Start the thread
                thread = instance_data['thread']
                thread.start()
                
                self.instances[tag] = instance_data
                success_count += 1
                print(f"✓ Started thread for instance '{tag}'")
            else:
                print(f"❌ Failed to start thread for instance '{tag}'")
        
        if success_count > 0:
            print(f"✓ Successfully started {success_count}/{len(self.config['instances'])} threads")
            self.running = True
            return True
        else:
            print("❌ Failed to start any threads")
            return False
    
    def stop_all_instances(self):
        """Stop all running instance threads and cleanup"""
        if not self.instances:
            print("ℹ️ No instances to stop")
            return
        
        print(f"🛑 Stopping {len(self.instances)} instance threads...")
        
        # Signal all threads to stop
        for tag, instance_data in self.instances.items():
            try:
                stop_event = instance_data["stop_event"]
                stop_event.set()
                print(f"   Signaled thread '{tag}' to stop")
            except Exception as e:
                print(f"   Warning: Error signaling '{tag}': {e}")
        
        # Wait for graceful shutdown
        print("   Waiting for threads to finish...")
        for tag, instance_data in self.instances.items():
            try:
                thread = instance_data["thread"]
                thread.join(timeout=10.0)  # 10 second timeout
                if thread.is_alive():
                    print(f"   Warning: Thread '{tag}' did not stop gracefully")
                else:
                    print(f"   ✓ Thread '{tag}' stopped")
            except Exception as e:
                print(f"   Warning: Error stopping '{tag}': {e}")
        
        # Run cleanup script
        print("🧹 Running cleanup...")
        try:
            subprocess.run(["python3", "cleanup_bpf.py", "--config", self.config_file], 
                        capture_output=True, check=False)
            print("✓ Cleanup completed")
        except Exception as e:
            print(f"Warning: Cleanup script error: {e}")
        
        self.instances.clear()
        self.running = False
        print("✓ All threads stopped")
    
    def check_instance_health(self):
        """Enhanced health checking of all running threads"""
        dead_instances = []
        
        for tag, instance_data in self.instances.items():
            thread = instance_data["thread"]
            config = instance_data["config"]
            
            if not thread.is_alive():
                dead_instances.append(tag)
                print(f"⚠️ Thread '{tag}' has died")
                
                # Attempt to diagnose
                diagnosis = self.diagnose_instance_failure(tag, config)
                print(f"🔍 {diagnosis}")
            else:
                # Thread is alive, check if output file is being updated
                output_file = config["output_file"]
                if os.path.exists(output_file):
                    file_age = time.time() - os.path.getmtime(output_file)
                    if file_age > 300:  # 5 minutes
                        print(f"⚠️ Thread '{tag}' output file stale ({file_age:.0f}s old)")
        
        # Remove dead instances
        for tag in dead_instances:
            del self.instances[tag]
            if self.debug:
                print(f"🗑️ Removed dead thread '{tag}' from monitoring")
        
        return len(dead_instances) == 0

    def collect_merged_data(self) -> Dict[str, Any]:
        """Collect and merge data from all instance output files"""
        merged_data = {"sources": []}
        
        for filename in sorted(self.summary_files):
            if self.debug:
                print(f"\n📂 Reading from: {filename}")
            
            file_data = self.read_summary_from_file(filename)
            if file_data and "sources" in file_data:
                # Add all sources from this file to merged data
                merged_data["sources"].extend(file_data["sources"])
                if self.debug:
                    print(f"   Added {len(file_data['sources'])} sources from {filename}")
        
        return merged_data

    def write_merged_traffic_file(self, merged_data: Dict[str, Any], output_path: str = "traffic.json"):
        """Write merged data to consolidated traffic.json file"""
        try:
            # Use atomic write with temporary file
            import tempfile
            import shutil
            
            temp_dir = os.path.dirname(output_path) or "."
            
            with tempfile.NamedTemporaryFile(
                mode='w', 
                dir=temp_dir, 
                prefix=f".{os.path.basename(output_path)}.tmp",
                suffix='.json',
                delete=False
            ) as temp_file:
                
                temp_path = temp_file.name
                json.dump(merged_data, temp_file, indent=2, default=str)
                temp_file.flush()
                os.fsync(temp_file.fileno())
            
            # Atomic move
            shutil.move(temp_path, output_path)
            
            if self.debug:
                source_count = len(merged_data.get("sources", []))
                print(f"✅ Merged traffic file updated: {source_count} sources -> {output_path}")
            
            return True
            
        except Exception as e:
            print(f"Error writing merged traffic file: {e}")
            if 'temp_path' in locals() and os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except:
                    pass
            return False

    def _check_instance_program_health_old(self, tag: str, config: Dict) -> bool:
        """Check if an instance has healthy eBPF program attachments"""
        try:
            interface = config["interface"]
            namespace = config.get("namespace")
            
            if namespace:
                cmd_prefix = ['ip', 'netns', 'exec', namespace]
            else:
                cmd_prefix = []
            
            # Check if any TC filters are attached
            check_cmd = cmd_prefix + ['tc', 'filter', 'show', 'dev', interface, 'ingress']
            result = subprocess.run(check_cmd, capture_output=True, text=True)
            ingress_filters = result.returncode == 0 and 'bpf' in result.stdout
            
            check_cmd = cmd_prefix + ['tc', 'filter', 'show', 'dev', interface, 'egress']
            result = subprocess.run(check_cmd, capture_output=True, text=True)
            egress_filters = result.returncode == 0 and 'bpf' in result.stdout
            
            if not (ingress_filters or egress_filters):
                if self.debug:
                    print(f"⚠️ Instance '{tag}' has no attached eBPF programs")
                return True  # Indicates there's an issue
            
            return False  # No issues detected
            
        except Exception as e:
            if self.debug:
                print(f"Health check error for '{tag}': {e}")
            return False
    
    def read_summary_from_file(self, filename: str) -> Dict[str, Any]:
        """Read summary data from a traffic stats file with file locking and retry mechanism"""
        max_retries = 10
        retry_delay = 0.1  # 100 milliseconds
        
        for attempt in range(max_retries):
            try:
                if not os.path.exists(filename):
                    if self.debug:
                        print(f"📂 File not found: {filename}")
                    return {}
                
                with open(filename, 'r') as f:
                    # Try to acquire shared lock for reading
                    try:
                        fcntl.flock(f.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
                    except (OSError, IOError):
                        # File is locked, retry
                        if attempt < max_retries - 1:
                            if self.debug:
                                print(f"📂 File {filename} is locked, retry {attempt + 1}/{max_retries}")
                            time.sleep(retry_delay)
                            continue
                        else:
                            if self.debug:
                                print(f"📂 File {filename} still locked after {max_retries} attempts, skipping")
                            return {}
                    
                    try:
                        data = json.load(f)
                        
                        # Handle both single-source and multi-source formats
                        if "sources" in data:
                            # Multi-source format
                            return data
                        else:
                            # Single-source format - convert to multi-source
                            return {
                                "sources": [{
                                    "id": "legacy",
                                    "metadata": data.get("metadata", {}),
                                    "summary": data.get("summary", {}),
                                    "protocol_breakdown": data.get("protocol_breakdown", {}),
                                    "whitelist_info": data.get("whitelist_info", {})
                                }]
                            }
                    except json.JSONDecodeError:
                        if self.debug:
                            print(f"⚠️ Invalid JSON in {filename}")
                        return {}
                        
            except Exception as e:
                if attempt < max_retries - 1:
                    if self.debug:
                        print(f"📂 Read attempt {attempt + 1} failed for {filename}: {e}, retrying...")
                    time.sleep(retry_delay)
                    continue
                else:
                    if self.debug:
                        print(f"Error reading {filename} after {max_retries} attempts: {e}")
                    return {}
        
        return {}
    
    def diagnose_instance_failure(self, tag: str, instance_config: Dict) -> str:
        """Diagnose why an instance might have failed"""
        issues = []
        
        # Check interface exists
        interface = instance_config["interface"]
        namespace = instance_config.get("namespace")
        
        try:
            if namespace:
                cmd = ["ip", "netns", "exec", namespace, "ip", "link", "show", interface]
            else:
                cmd = ["ip", "link", "show", interface]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                issues.append(f"Interface '{interface}' not found in namespace '{namespace or 'host'}'")
        except Exception as e:
            issues.append(f"Could not check interface: {e}")
        
        # Check output file permissions
        output_file = instance_config["output_file"]
        output_dir = os.path.dirname(output_file) or "."
        if not os.access(output_dir, os.W_OK):
            issues.append(f"Cannot write to output directory: {output_dir}")
        
        # Check whitelist file
        whitelist_file = instance_config.get("whitelist_file")
        if whitelist_file and not os.path.exists(whitelist_file):
            issues.append(f"Whitelist file not found: {whitelist_file}")
        
        # Check for common eBPF issues
        try:
            result = subprocess.run(["bpftool", "prog", "list"], capture_output=True, text=True)
            if result.returncode != 0:
                issues.append("bpftool not working - eBPF subsystem issue")
        except FileNotFoundError:
            issues.append("bpftool not found")
    
        return f"Possible issues for '{tag}': " + "; ".join(issues) if issues else f"No obvious issues found for '{tag}'"

    def format_bytes(self, bytes_count: int) -> str:
        """Format bytes in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_count < 1024.0:
                return f"{bytes_count:.2f} {unit}"
            bytes_count /= 1024.0
        return f"{bytes_count:.2f} PB"
    
    def display_summary(self):
        """Display summary statistics from all monitored files"""
        print(f"\n{'='*100}")
        print(f"📊 NETWORK ACCOUNTING SUMMARY - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*100}")
        
        total_sources = 0
        grand_total_rx = 0
        grand_total_tx = 0
        all_protocols = {}
        
        # Read data from all summary files
        for filename in sorted(self.summary_files):
            if self.debug:
                print(f"\n📂 Reading summary from: {filename}")
            
            file_data = self.read_summary_from_file(filename)
            if not file_data or "sources" not in file_data:
                if self.debug:
                    print(f"   No data found in {filename}")
                continue
            
            # Process each source in the file
            for source in file_data["sources"]:
                source_id = source.get("id", "unknown")
                metadata = source.get("metadata", {})
                summary = source.get("summary", {})
                protocols = source.get("protocol_breakdown", {})
                whitelist = source.get("whitelist_info", {})
                
                if not summary:
                    continue
                
                total_sources += 1
                
                # Extract data
                interface = metadata.get("interface", "unknown")
                namespace = metadata.get("namespace", "host")
                last_updated = metadata.get("last_updated", "unknown")
                total_entries = metadata.get("total_entries", 0)
                whitelisted_count = metadata.get("whitelisted_ips_count", 0)
                
                rx_bytes = summary.get("total_rx_bytes", 0)
                tx_bytes = summary.get("total_tx_bytes", 0)
                total_bytes = summary.get("total_bytes", 0)
                unique_sources = summary.get("unique_source_ips", 0)
                unique_destinations = summary.get("unique_destination_ips", 0)
                
                # Accumulate grand totals
                grand_total_rx += rx_bytes
                grand_total_tx += tx_bytes
                
                # Accumulate protocol stats
                for proto, proto_stats in protocols.items():
                    if proto not in all_protocols:
                        all_protocols[proto] = {"count": 0, "rx_bytes": 0, "tx_bytes": 0, "total_bytes": 0}
                    all_protocols[proto]["count"] += proto_stats.get("count", 0)
                    all_protocols[proto]["rx_bytes"] += proto_stats.get("rx_bytes", 0)
                    all_protocols[proto]["tx_bytes"] += proto_stats.get("tx_bytes", 0)
                    all_protocols[proto]["total_bytes"] += proto_stats.get("total_bytes", 0)
                
                # Display source summary
                print(f"\n🌐 Source: {source_id}")
                print(f"   Interface: {interface} (Namespace: {namespace})")
                print(f"   Last Updated: {last_updated}")
                print(f"   Active Flows: {total_entries}")
                print(f"   Unique IPs: {unique_sources} sources → {unique_destinations} destinations")
                print(f"   Whitelisted: {whitelisted_count} IPs")
                print(f"   Traffic: RX={self.format_bytes(rx_bytes)}, TX={self.format_bytes(tx_bytes)}, Total={self.format_bytes(total_bytes)}")
                
                # Show protocol breakdown for this source
                if protocols:
                    protocol_summary = ", ".join([f"{proto}({stats['count']} flows)" for proto, stats in protocols.items()])
                    print(f"   Protocols: {protocol_summary}")
        
        # Display grand totals
        if total_sources > 0:
            print(f"\n{'='*50}")
            print(f"📈 GRAND TOTALS ({total_sources} sources)")
            print(f"{'='*50}")
            print(f"Total RX: {self.format_bytes(grand_total_rx)}")
            print(f"Total TX: {self.format_bytes(grand_total_tx)}")
            print(f"Total Traffic: {self.format_bytes(grand_total_rx + grand_total_tx)}")
            
            # Display protocol totals
            if all_protocols:
                print(f"\n📊 Protocol Breakdown:")
                for proto, stats in sorted(all_protocols.items()):
                    print(f"   {proto}: {stats['count']} flows, {self.format_bytes(stats['total_bytes'])}")
        else:
            print("\n⚠️ No summary data found in any monitored files")
        
        print(f"{'='*100}")
    
    def monitor_instances(self):
        """Monitor running threads and create merged output"""
        print(f"\n🔄 Monitoring {len(self.instances)} instance threads...")
        print("   Press Ctrl+C to stop all threads and exit")
        
        if self.debug:
            print(f"🐛 Manager debug mode - showing detailed monitoring information")
        
        iteration = 0
        while self.running:
            try:
                # Check thread health
                if not self.check_instance_health():
                    if not self.instances:
                        print("❌ All threads have died, exiting...")
                        break
                
                # Collect and merge data every iteration (every 5 seconds)
                if self.debug:
                    print(f"\n🔄 Iteration {iteration}: Collecting and merging data...")
                
                # Collect merged data from all instance files
                merged_data = self.collect_merged_data()
                
                # Write merged data to traffic.json
                if merged_data.get("sources"):
                    self.write_merged_traffic_file(merged_data, "traffic.json")
                
                # Display summary every 5 iterations (25 seconds)
                if iteration % 5 == 0:
                    self.display_summary()
                
                # Show thread status in debug mode every 10 iterations
                if self.debug and iteration % 10 == 0:
                    print(f"\n🔍 Thread Health Check (iteration {iteration}):")
                    for tag, instance_data in self.instances.items():
                        thread = instance_data["thread"]
                        config = instance_data["config"]
                        uptime = datetime.now() - instance_data["start_time"]
                        status = "Running" if thread.is_alive() else "Dead"
                        
                        # Check output file
                        output_file = config["output_file"]
                        file_info = ""
                        try:
                            if os.path.exists(output_file):
                                file_size = os.path.getsize(output_file)
                                file_age = time.time() - os.path.getmtime(output_file)
                                file_info = f", output_size={self.format_bytes(file_size)}, age={file_age:.0f}s"
                            else:
                                file_info = ", output=missing"
                        except Exception as e:
                            file_info = f", output_error={e}"
                        
                        print(f"   {tag}: {status} (uptime: {uptime}{file_info})")
                
                time.sleep(5)
                iteration += 1
                
            except KeyboardInterrupt:
                print("\n🛑 Interrupt received...")
                break
            except Exception as e:
                print(f"Error in monitoring loop: {e}")
                if self.debug:
                    import traceback
                    traceback.print_exc()
                break
        
        self.running = False
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print(f"\n🛑 Received signal {signum}, shutting down...")
        self.running = False
    
    def run(self):
        """Main run method"""
        try:
            if not self.load_config():
                return False
            
            if not self.start_all_instances():
                return False
            
            self.monitor_instances()
            
            return True
            
        except Exception as e:
            print(f"❌ Error in main run: {e}")
            return False
        finally:
            self.stop_all_instances()


def create_example_config():
    """Create an example configuration file"""
    example_config = {
        "instances": [
            {
                "tag": "gbb",
                "namespace": "gbb",
                "interface": "data-apn",
                "output_file": "traffic_stats.json",
                "whitelist_file": "gbb_whitelist.json",
                "tc_ingress": True,
                "debug": True
            },
            {
                "tag": "bear-develop",
                "namespace": None,
                "interface": "bear-develop",
                "output_file": "bear-traffic_stats.json",
                "whitelist_file": "bear-develop_whitelist.json",
                "tc_ingress": True,
                "debug": True
            },
            {
                "tag": "atg4g",
                "namespace": "atg4g",
                "interface": "eth0",
                "output_file": "traffic_stats.json",
                "whitelist_file": "atg_whitelist.json",
                "tc_ingress": True,
                "debug": False
            }
        ]
    }
    
    config_file = "multi_accounting_config.json"
    try:
        with open(config_file, 'w') as f:
            json.dump(example_config, f, indent=2)
        print(f"✓ Created example configuration: {config_file}")
        return True
    except Exception as e:
        print(f"❌ Error creating example config: {e}")
        return False


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Multi-Instance Network Accounting Manager',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s config.json                    # Run with configuration file
  %(prog)s --create-example               # Create example configuration
  %(prog)s --summary-only config.json    # Display summary only (no instances)
  %(prog)s --debug config.json           # Run with debug output

Configuration Format:
  {
    "instances": [
      {
        "tag": "unique-identifier",
        "namespace": "namespace-name or null",
        "interface": "interface-name",
        "output_file": "output-file.json",
        "whitelist_file": "whitelist.json",
        "tc_ingress": true,
        "debug": false
      }
    ]
  }
        """
    )
    
    parser.add_argument('config_file', nargs='?', help='Configuration file path')
    parser.add_argument('--create-example', '-e', action='store_true',
                       help='Create example configuration file')
    parser.add_argument('--summary-only', '-s', action='store_true',
                       help='Display summary only without starting instances')
    parser.add_argument('--debug', '-d', action='store_true',
                       help='Enable debug output')
    
    args = parser.parse_args()
    
    # Check root privileges
    if os.geteuid() != 0 and not args.create_example and not args.summary_only:
        print("❌ This program requires root privileges to run network accounting instances.")
        print(f"Please run: sudo python3 {' '.join(sys.argv)}")
        sys.exit(1)
    
    if args.create_example:
        if create_example_config():
            sys.exit(0)
        else:
            sys.exit(1)
    
    if not args.config_file:
        print("❌ Configuration file required")
        print(f"Usage: python3 {sys.argv[0]} <config_file>")
        print(f"Create example: python3 {sys.argv[0]} --create-example")
        sys.exit(1)
    
    # Create manager
    manager = MultiNetworkAccountingManager(args.config_file, debug=args.debug)
    
    if args.summary_only:
        # Load config and display summary only
        if manager.load_config():
            manager.display_summary()
            sys.exit(0)
        else:
            sys.exit(1)
    
    # Run the manager
    success = manager.run()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()