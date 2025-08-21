#!/usr/bin/env python3

"""
Network Accounting eBPF Module
A modular, high-performance network traffic accounting system using eBPF
with configurable ingress methods, namespace support, and whitelist functionality.
"""

import os
import time
import sys
from datetime import datetime
from typing import Optional, Dict
import signal
import sys
import atexit
import time
# Handle imports for both direct execution and package usage
try:
    from .utils import check_root_privileges, ip_to_string, format_bytes
    from .network_interface import NetworkInterface, NetworkTopology
    from .whitelist_manager import WhitelistManager
    from .output_writer import OutputWriter, OutputFormat
    from .bpf_manager import BPFProgramManager
    from .program_attacher import ProgramAttacher
    from .stats_collector import StatsCollector
except ImportError:
    # Fallback for direct execution
    from utils import check_root_privileges, ip_to_string, format_bytes
    from network_interface import NetworkInterface, NetworkTopology
    from whitelist_manager import WhitelistManager
    from output_writer import OutputWriter, OutputFormat
    from bpf_manager import BPFProgramManager
    from program_attacher import ProgramAttacher
    from stats_collector import StatsCollector

# Global reference to the monitor instance for cleanup
_current_monitor = None


def signal_handler(signum, frame):
    """Handle SIGINT (Ctrl+C) gracefully"""
    global _current_monitor
    print(f"\n🛑 Interrupt received, cleaning up...")
    # To be done later as of now handle cleanup in local context 
    sys.exit(0)
    
    if _current_monitor:
        _current_monitor.cleanup()
    
    print("👋 Cleanup completed, exiting...")
    sys.exit(0)

def register_cleanup_handlers(monitor):
    """Register signal and exit handlers"""
    global _current_monitor
    _current_monitor = monitor
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    atexit.register(lambda: monitor.cleanup() if monitor else None)


class NetworkAccountingModule:
    """Main network accounting module with namespace support and configurable ingress methods"""
    
    def __init__(self, interface: str, output_file: str = None, 
            whitelist_file: str = None, namespace: Optional[str] = None,
            use_tc_ingress: bool = False, debug: bool = False, 
            tag: str = None, flush_after_read: bool = True, thread_mode: bool = False):

        self.interface = interface
        self.namespace = namespace
        self.use_tc_ingress = use_tc_ingress
        self.network_interface = NetworkInterface(interface, namespace)
        self.flush_after_read = flush_after_read
        self.thread_mode = thread_mode  # NEW: Track if running in thread mode
        self.debug = debug
        
        # Resolve file paths relative to project root
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(script_dir)  # Go up from useracct/ to project root
        
        # Set default paths if not provided
        if output_file is None:
            self.output_file = os.path.join(project_root, "logs", "traffic_stats.json")
        else:
            # If it's a relative path, make it relative to project root
            if not os.path.isabs(output_file):
                # Check if it's already in the correct folder structure
                if output_file.startswith(('logs/', 'config/', 'ebpf/')):
                    self.output_file = os.path.join(project_root, output_file)
                else:
                    # Assume it's in logs folder
                    self.output_file = os.path.join(project_root, "logs", output_file)
            else:
                self.output_file = output_file
                
        if whitelist_file is None:
            self.whitelist_file = os.path.join(project_root, "config", "whitelist.json")
        else:
            # If it's a relative path, make it relative to project root
            if not os.path.isabs(whitelist_file):
                # Check if it's already in the correct folder structure
                if whitelist_file.startswith(('logs/', 'config/', 'ebpf/')):
                    self.whitelist_file = os.path.join(project_root, whitelist_file)
                else:
                    # Assume it's in config folder
                    self.whitelist_file = os.path.join(project_root, "config", whitelist_file)
            else:
                self.whitelist_file = whitelist_file
        
        # Thread-specific initialization
        if thread_mode:
            # Don't register global signal handlers in thread mode
            if self.debug:
                print(f"[{tag or interface}] 🧵 Running in thread mode - skipping signal handler registration")
        else:
            print(f"[{tag or interface}] 🧵 Running in standalone mode - registering signal handler")
            # Register signal handlers only for standalone mode
            register_cleanup_handlers(self)

        output_dir = os.path.dirname(self.output_file) if os.path.dirname(self.output_file) else "."
       
        # Initialize managers
        self.whitelist_manager = WhitelistManager(self.whitelist_file, output_dir, debug=debug)
        self.output_writer = OutputWriter(self.output_file, debug=debug, namespace=namespace, interface=interface, flush_after_read=flush_after_read  )
        # Auto-generate object file based on tag
        if tag and tag != "default":
            object_file = f"build/objects/network_accounting_{tag}.bpf.o"
        else:
            object_file = None  # Will use default path resolution

        # Verify object file exists, fallback to default if not found
        if object_file and not os.path.exists(os.path.join(project_root, object_file)):
            object_file = None  # Use default

        self.bpf_manager = BPFProgramManager(interface, namespace, use_tc_ingress, debug=debug, object_file=object_file, tag=tag)

        self.program_attacher = ProgramAttacher(interface, namespace, use_tc_ingress, debug=debug)
        self.stats_collector = StatsCollector(self.whitelist_manager, debug=debug)

        
        # Display configuration
        
        print(f"📡 Interface: {interface}")
        if namespace:
            print(f"🏷️  Namespace: {namespace}")
        print(f"📈 Ingress method: {'TC' if use_tc_ingress else 'XDP'}")
        print(f"📄 Output: {self.output_file}")
        print(f"📋 Whitelist: {self.whitelist_file}")
        
        # Show helpful info if no whitelist exists
        if not self.whitelist_manager.load_whitelist():
            print(f"💡 Create a whitelist file to exclude specific IPs from accounting:")
            print(f"   python3 network_accounting.py --create-examples")
    
    def load_bpf_program(self) -> bool:
        """Load and attach eBPF programs"""
        try:
            if self.debug:
                print("\n🔄 Initializing BPF program...")
            
            # Step 1: Initialize BPF (verify files, prepare for attachment)
            if not self.bpf_manager.load_functions():
                print("❌ Failed to initialize BPF")
                return False
            
            # Step 2: Attach programs to interface FIRST (for TC mode)
            print("\n🔄 Attaching programs to interface...")
            if not self.program_attacher.attach_programs(self.bpf_manager):
                print("❌ Failed to attach programs")
                return False
            
            # Step 3: Get map references (after attachment for TC mode)
            if self.debug:
                print("\n🔄 Getting map references...")
            traffic_map, whitelist_map = self.bpf_manager.get_maps()
            
            if traffic_map is None or whitelist_map is None:
                print("❌ Failed to get map references")
                return False
            
            if self.debug:
                print("✓ Maps initialized successfully")
            
            # Step 4: Load and populate whitelist
            if self.whitelist_manager.load_whitelist():
                if self.debug:
                    print("📋 Populating whitelist map...")
                self.whitelist_manager.populate_bpf_map(whitelist_map)
            
            # Store map references for monitoring loop
            self.traffic_map = traffic_map
            self.whitelist_map = whitelist_map
            
            return True
            
        except Exception as e:
            print(f"❌ Error in BPF program setup: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def run_monitoring(self, stop_event=None):
        """Thread-safe monitoring loop for multi-instance mode"""
        if self.debug:
            print(f"🚀 Starting thread-safe network traffic monitoring for {self.interface}")
        
        try:
            # Get maps references once at startup
            traffic_map, whitelist_map = self.bpf_manager.get_maps()
            
            if traffic_map is None or whitelist_map is None:
                print("❌ BPF maps not properly initialized.")
                return
            
            iteration = 0
            last_health_check = 0

            while True:
                # Check stop event if provided
                if stop_event and stop_event.is_set():
                    if self.debug:
                        print(f"🛑 Stop event received for {self.interface}")
                    break
                
                # Health check every 20 iterations (100 seconds)
                if iteration - last_health_check >= 20:
                    if not self._check_program_health():
                        print(f"⚠️ Program health check failed for {self.interface}")
                        if not self._recover_programs():
                            print(f"❌ Program recovery failed for {self.interface}, stopping...")
                            break
                    last_health_check = iteration

                # Reload whitelist if changed (every 10 iterations)
                if iteration % 10 == 0:
                    self.whitelist_manager.reload_if_changed(whitelist_map)

                # Collect stats data
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                stats_data = self.stats_collector.collect_stats(traffic_map, flush_after_read=self.flush_after_read)
                whitelist_info = self.stats_collector.get_whitelist_info()
                
                # ALWAYS write to file
                write_success = self.output_writer.write_stats(
                    stats_data, timestamp, whitelist_info
                )

                # Minimal console output in thread mode
                if stats_data:
                    if self.debug:
                        self.output_writer.display_new_data_stats(
                            stats_data, timestamp, whitelist_info
                        )
                    else:
                        # Just log activity, don't spam console
                        print(f"[{self.interface}] 🔄 {timestamp}: {len(stats_data)} flows")
                
                # Use stop event for timing if available
                if stop_event:
                    if stop_event.wait(timeout=5.0):
                        break
                else:
                    time.sleep(5)
                
                iteration += 1
                    
        except KeyboardInterrupt:
            if self.debug:
                print(f"\n🛑 Keyboard interrupt received for {self.interface}")
        except Exception as e:
            print(f"\n❌ Error in monitoring loop for {self.interface}: {e}")
            if self.debug:
                import traceback
                traceback.print_exc()
        finally:
            if not self.thread_mode:
                self.cleanup()

    def run_monitoring_old(self):
        """Main monitoring loop with health checking"""
        ingress_method = "TC" if self.use_tc_ingress else "XDP"
        print(f"🚀 Starting network traffic monitoring ")
        if self.debug:
            print("Press Ctrl+C to stop...")
            print("Note: It may take a few moments to see traffic data.")
        
        try:
            # Get maps references once at startup
            traffic_map, whitelist_map = self.bpf_manager.get_maps()
            
            if traffic_map is None or whitelist_map is None:
                print("❌ BPF maps not properly initialized.")
                return
            
            if self.debug:
                print("✓ BPF maps initialized successfully")
                print("✓ Starting monitoring loop...")
            
            iteration = 0
            last_health_check = 0

            while True:
                # Health check every 20 iterations (100 seconds)
                if iteration - last_health_check >= 20:
                    if not self._check_program_health():
                        print("⚠️ Program health check failed, attempting recovery...")
                        if not self._recover_programs():
                            print("❌ Program recovery failed, exiting...")
                            break
                    last_health_check = iteration

                # Reload whitelist if changed (every 10 iterations)
                if iteration % 10 == 0:
                    if self.debug:
                        traffic_map_name = getattr(traffic_map, 'name', 'unknown')
                        traffic_map_id = getattr(traffic_map, 'map_id', 0)  
                        print(f"Traffic map Name='{traffic_map_name}', ID={traffic_map_id}")
                        self.bpf_manager.debug_map_contents()
                    self.whitelist_manager.reload_if_changed(whitelist_map)

                # Collect stats data - THIS SHOULD ALWAYS HAPPEN
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                stats_data = self.stats_collector.collect_stats(traffic_map, flush_after_read=self.flush_after_read)
                whitelist_info = self.stats_collector.get_whitelist_info()
                

               # ALWAYS write to file (not debug-dependent)
                write_success = self.output_writer.write_stats(
                    stats_data, timestamp, whitelist_info
                )

                # Unified display logic - always show what we collected
                if stats_data:
                    if self.debug:
                        # Debug mode: show detailed new data with debug info
                        self.output_writer.display_new_data_stats(
                            stats_data, timestamp, whitelist_info
                        )
                    else:
                        # Normal mode: show data in accumulated format but use collected data
                        # Convert collected data to accumulated display format
                        accumulated_format_data = []
                        for entry in stats_data:
                            accumulated_format_data.append({
                                'source_ip': ip_to_string(entry['src_ip']),
                                'destination_ip': ip_to_string(entry['dst_ip']),
                                'protocol': entry['protocol'],
                                'rx_bytes': entry['rx_bytes'],
                                'tx_bytes': entry['tx_bytes'],
                                'total_bytes': entry['rx_bytes'] + entry['tx_bytes'],
                                'rx_formatted': format_bytes(entry['rx_bytes']),
                                'tx_formatted': format_bytes(entry['tx_bytes']),
                                'total_formatted': format_bytes(entry['rx_bytes'] + entry['tx_bytes'])
                            })
                        
                        self.output_writer.display_console_stats(
                            accumulated_format_data, timestamp, whitelist_info
                        )
                else:
                    print(f"🔄 {timestamp}: No new traffic data this poll")

                
                time.sleep(5)
                iteration += 1
                    
        except KeyboardInterrupt:
            print("\n🛑 Keyboard interrupt received in monitoring loop")
        except Exception as e:
            print(f"\n❌ Error in monitoring loop: {e}")
            self.cleanup()
            raise

    def _check_program_health(self) -> bool:
        """Check if our eBPF programs are still attached"""
        try:
            import subprocess
            import json
            
            # Check if our programs are still loaded
            result = subprocess.run(['bpftool', 'prog', 'list', '-j'], 
                                capture_output=True, text=True)
            if result.returncode != 0:
                return False
            
            programs = json.loads(result.stdout)
            target_programs = {'xdp_traffic_accounting', 'tc_traffic_in', 'tc_traffic_eg', 
                            'classifier/ingress', 'classifier/egress'}
            
            found_programs = set()
            for prog in programs:
                prog_name = prog.get('name', '')
                if prog_name in target_programs:
                    found_programs.add(prog_name)
            
            # Check TC filters are still attached
            if self.namespace:
                cmd_prefix = ['ip', 'netns', 'exec', self.namespace]
            else:
                cmd_prefix = []
            
            # Check ingress filters
            check_cmd = cmd_prefix + ['tc', 'filter', 'show', 'dev', self.interface, 'ingress']
            result = subprocess.run(check_cmd, capture_output=True, text=True)
            ingress_attached = result.returncode == 0 and 'bpf' in result.stdout
            
            # Check egress filters
            egress_interface = self.network_interface.get_parent_interface()
            check_cmd = cmd_prefix + ['tc', 'filter', 'show', 'dev', egress_interface, 'egress']
            result = subprocess.run(check_cmd, capture_output=True, text=True)
            egress_attached = result.returncode == 0 and 'bpf' in result.stdout
            
            if self.debug:
                print(f"🔍 Health check: programs={len(found_programs)}, ingress={ingress_attached}, egress={egress_attached}")
            
            # We need at least 2 programs (ingress + egress) for proper accounting
            expected_count = 2 if self.use_tc_ingress else 3  # XDP + TC egress vs TC ingress + TC egress
            return len(found_programs) >= expected_count and (ingress_attached or not self.use_tc_ingress) and egress_attached
            
        except Exception as e:
            if self.debug:
                print(f"Health check error: {e}")
            return False

    def _recover_programs(self) -> bool:
        """Attempt to recover failed programs"""
        try:
            if self.debug:
                print("🔧 Attempting program recovery...")
            
            # Cleanup any remaining programs
            self.cleanup()
            time.sleep(2)
            
            # Reload programs
            return self.load_bpf_program()
            
        except Exception as e:
            print(f"Recovery failed: {e}")
            return False

    def cleanup(self):
        """Clean up BPF programs and TC filters"""
        self.program_attacher.cleanup(self.bpf_manager)

    

def main():
    """Main entry point with argument parsing"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Network Accounting eBPF Module with Configurable Ingress Methods',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s eth0                                    # Basic monitoring (XDP ingress)
  %(prog)s eth0 --xdp                              # Use XDP for ingress instead of TC
  %(prog)s eth0 ../logs/stats.json ../config/whitelist.json          # Custom files
  %(prog)s --namespace myns eth0                   # Namespace monitoring
  %(prog)s --list-all                              # List interfaces
  %(prog)s --create-examples                       # Create example files

Ingress Methods:
    TC (default):   More flexible, better namespace support, easier debugging
    XDP (optional): Fast kernel-level packet processing, ideal for high throughput
        """
    )
    
    parser.add_argument('interface', nargs='?', help='Network interface to monitor')
    parser.add_argument('output_file', nargs='?', default=None, 
                       help='Output file (default: logs/traffic_stats.json)')
    parser.add_argument('whitelist_file', nargs='?', default=None,
                       help='Whitelist file (default: config/whitelist.json)')
    parser.add_argument('--namespace', '-n', help='Network namespace')
    parser.add_argument('--xdp', action='store_true',
                       help='Use XDP for ingress instead of TC (higher performance)')
    parser.add_argument('--list-all', '-l', action='store_true', 
                       help='List all interfaces in all namespaces')
    parser.add_argument('--create-examples', '-e', action='store_true',
                       help='Create example configuration files')
    parser.add_argument('--object-file', help='BPF object file to use (default: build/objects/network_accounting.bpf.o)')
    parser.add_argument('--debug', '-d', action='store_true',
                   help='Enable debug output and detailed logging')
    parser.add_argument('--tag', help='Instance tag for map naming')
    parser.add_argument('--flush-after-read', default=True, action='store_true',
                   help='Flush BPF map after reading')

    
    args = parser.parse_args()
    
    # Handle special commands
    if args.list_all:
        NetworkTopology.list_all_interfaces()
        if not args.interface:
            sys.exit(0)
    
    if args.create_examples:
        # Create whitelist examples
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(script_dir)
        whitelist_path = os.path.join(project_root, "config", "whitelist.json")
        wm = WhitelistManager(whitelist_path)
        wm.create_example_json(whitelist_path)
        print("✓ Example whitelist files created")
        if not args.interface:
            sys.exit(0)
    
    if not args.interface:
        print("Usage: python3 network_accounting.py <interface> [output_file] [whitelist_file]")
        print("\nAvailable interfaces:")
        interfaces = NetworkTopology.get_interfaces()
        for iface in interfaces:
            ni = NetworkInterface(iface)
            status = "UP" if ni.is_up() else "DOWN"
            print(f"  📡 {iface} ({status})")
        
        print(f"\nFor more options: python3 {sys.argv[0]} --help")
        sys.exit(1)
    
    # Check root privileges
    check_root_privileges()
    
    # Validate interface
    if not NetworkTopology.validate_interface(args.interface, args.namespace):
        print(f"❌ Interface '{args.interface}' not found or not up")
        
        ns_text = f" in namespace {args.namespace}" if args.namespace else ""
        print(f"\nAvailable interfaces{ns_text}:")
        
        interfaces = NetworkTopology.get_interfaces(args.namespace)
        for iface in interfaces:
            ni = NetworkInterface(iface, args.namespace)
            status = "UP" if ni.is_up() else "DOWN"
            print(f"  📡 {iface} ({status})")
        
        sys.exit(1)
    
    if args.debug:
        print(f"✓ Interface '{args.interface}' is ready")
    
    # Show XDP performance note for high throughput
    if not args.namespace and not args.xdp:
        print("💡 For maximum performance on host interfaces, consider using --xdp")


    # Create and run the monitor
    monitor = NetworkAccountingModule(
        interface=interface,
        output_file=output_file,
        whitelist_file=whitelist_file,
        namespace=namespace,
        use_tc_ingress=True,  # Always use TC for thread mode
        debug=debug,
        tag=tag,
        flush_after_read=True,
        thread_mode=True  # Add this line
    )


    if monitor.load_bpf_program():
        monitor.run_monitoring()
    else:
        print("❌ Failed to load BPF program")
        sys.exit(1)


if __name__ == "__main__":
    main()