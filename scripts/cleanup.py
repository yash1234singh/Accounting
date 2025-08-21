#!/usr/bin/env python3

"""
Enhanced eBPF Network Accounting Cleanup Script
Forcefully removes all BPF programs and TC filters across all interfaces and namespaces
Best-effort cleanup with minimal error output
"""

import subprocess
import json
import sys
import os
from typing import List, Dict, Optional, Set


class EnhancedBPFCleanupTool:
    """Comprehensive cleanup tool for eBPF programs and TC filters across all interfaces and namespaces"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.cleaned_programs = []
        self.cleaned_maps = []
        self.cleaned_tc_filters = []
        self.cleaned_xdp_programs = []
        
        # Target program and map names for network accounting
        self.target_program_names = {
            'xdp_traffic_accounting',
            'xdp_traffic_accounting_by_source', 
            'tc_traffic_in',
            'tc_traffic_eg',
            'tc_traffic_accounting_ingress_by_source',
            'classifier/ingress',
            'classifier/egress'
        }
        
        self.target_map_names = {
            'traffic_map',
            'whitelist_map'
        }
    
    def log(self, message: str, force: bool = False):
        """Log message if verbose or forced"""
        if self.verbose or force:
            print(message)
    
    def run_command_silent(self, cmd: List[str]) -> subprocess.CompletedProcess:
        """Execute system command silently (best effort)"""
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=10  # Add timeout to prevent hanging
            )
            return result
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError, OSError):
            # Return a failed result without raising exceptions
            return subprocess.CompletedProcess(cmd, 1, "", "")
    
    def get_all_namespaces(self) -> List[str]:
        """Get all network namespaces"""
        try:
            result = self.run_command_silent(['ip', 'netns', 'list'])
            if result.returncode != 0:
                return []
            
            namespaces = []
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    ns_name = line.strip().split()[0]
                    namespaces.append(ns_name)
            return namespaces
        except Exception:
            return []
    
    def get_interfaces_in_namespace(self, namespace: Optional[str] = None) -> List[str]:
        """Get network interfaces in a specific namespace"""
        try:
            if namespace:
                cmd = ['ip', 'netns', 'exec', namespace, 'ip', 'link', 'show']
            else:
                cmd = ['ip', 'link', 'show']
            
            result = self.run_command_silent(cmd)
            if result.returncode != 0:
                return []
            
            interfaces = []
            for line in result.stdout.split('\n'):
                if ': ' in line and not line.startswith(' '):
                    parts = line.split(': ')
                    if len(parts) >= 2:
                        iface_name = parts[1].split('@')[0]
                        # Include all interfaces, even lo for thorough cleanup
                        interfaces.append(iface_name)
            
            return interfaces
        except Exception:
            return []
    
    def get_all_interfaces_across_namespaces(self) -> Dict[str, List[str]]:
        """Get all interfaces across all namespaces"""
        all_interfaces = {}
        
        # Host namespace
        host_interfaces = self.get_interfaces_in_namespace(None)
        if host_interfaces:
            all_interfaces['host'] = host_interfaces
        
        # All named namespaces
        namespaces = self.get_all_namespaces()
        for ns in namespaces:
            ns_interfaces = self.get_interfaces_in_namespace(ns)
            if ns_interfaces:
                all_interfaces[ns] = ns_interfaces
        
        return all_interfaces
    
    def cleanup_xdp_programs_comprehensive(self) -> bool:
        """Remove XDP programs from all interfaces across all namespaces"""
        self.log("🔄 Comprehensive XDP cleanup across all namespaces...")
        cleaned_any = False
        
        all_interfaces = self.get_all_interfaces_across_namespaces()
        
        for ns_name, interfaces in all_interfaces.items():
            for interface in interfaces:
                try:
                    if ns_name == 'host':
                        # Host namespace
                        cmd = ['ip', 'link', 'set', interface, 'xdp', 'off']
                    else:
                        # Named namespace
                        cmd = ['ip', 'netns', 'exec', ns_name, 'ip', 'link', 'set', interface, 'xdp', 'off']
                    
                    result = self.run_command_silent(cmd)
                    if result.returncode == 0:
                        self.log(f"✓ Removed XDP from {interface} ({ns_name})")
                        self.cleaned_xdp_programs.append(f"XDP:{ns_name}:{interface}")
                        cleaned_any = True
                
                except Exception:
                    continue  # Best effort, continue with next interface
        
        if not cleaned_any and self.verbose:
            self.log("ℹ️  No XDP programs found to remove")
        
        return cleaned_any
    
    def cleanup_tc_filters_comprehensive(self) -> bool:
        """Remove TC filters from all interfaces across all namespaces"""
        self.log("🔄 Comprehensive TC cleanup across all namespaces...")
        cleaned_any = False
        
        all_interfaces = self.get_all_interfaces_across_namespaces()
        
        for ns_name, interfaces in all_interfaces.items():
            for interface in interfaces:
                try:
                    if ns_name == 'host':
                        cmd_prefix = []
                    else:
                        cmd_prefix = ['ip', 'netns', 'exec', ns_name]
                    
                    # Clean ingress filters
                    clean_cmd = cmd_prefix + ['tc', 'filter', 'del', 'dev', interface, 'ingress']
                    result = self.run_command_silent(clean_cmd)
                    if result.returncode == 0:
                        self.log(f"✓ Removed TC ingress filters from {interface} ({ns_name})")
                        self.cleaned_tc_filters.append(f"ingress:{ns_name}:{interface}")
                        cleaned_any = True
                    
                    # Clean egress filters
                    clean_cmd = cmd_prefix + ['tc', 'filter', 'del', 'dev', interface, 'egress']
                    result = self.run_command_silent(clean_cmd)
                    if result.returncode == 0:
                        self.log(f"✓ Removed TC egress filters from {interface} ({ns_name})")
                        self.cleaned_tc_filters.append(f"egress:{ns_name}:{interface}")
                        cleaned_any = True
                    
                    # Remove clsact qdisc (this will remove all associated filters)
                    clean_cmd = cmd_prefix + ['tc', 'qdisc', 'del', 'dev', interface, 'clsact']
                    result = self.run_command_silent(clean_cmd)
                    if result.returncode == 0:
                        self.log(f"✓ Removed clsact qdisc from {interface} ({ns_name})")
                        cleaned_any = True
                    
                    # Also try to remove any other TC qdiscs that might interfere
                    for qdisc_type in ['clsact', 'ingress', 'handle']:
                        clean_cmd = cmd_prefix + ['tc', 'qdisc', 'del', 'dev', interface, qdisc_type]
                        self.run_command_silent(clean_cmd)  # Best effort, ignore results
                
                except Exception:
                    continue  # Best effort, continue with next interface
        
        if not cleaned_any and self.verbose:
            self.log("ℹ️  No TC filters found to remove")
        
        return cleaned_any
    
    def get_all_bpf_programs(self) -> List[Dict]:
        """Get list of all loaded BPF programs"""
        try:
            result = self.run_command_silent(['bpftool', 'prog', 'list', '-j'])
            if result.returncode != 0:
                return []
            
            try:
                programs = json.loads(result.stdout)
                return programs if isinstance(programs, list) else []
            except json.JSONDecodeError:
                return []
        except Exception:
            return []
    
    def get_all_bpf_maps(self) -> List[Dict]:
        """Get list of all loaded BPF maps"""
        try:
            result = self.run_command_silent(['bpftool', 'map', 'list', '-j'])
            if result.returncode != 0:
                return []
            
            try:
                maps = json.loads(result.stdout)
                return maps if isinstance(maps, list) else []
            except json.JSONDecodeError:
                return []
        except Exception:
            return []
    
    def cleanup_network_accounting_programs_comprehensive(self) -> bool:
        """Remove all network accounting BPF programs"""
        self.log("🔄 Comprehensive BPF program cleanup...")
        
        programs = self.get_all_bpf_programs()
        cleaned_any = False
        
        for program in programs:
            prog_id = program.get('id')
            prog_name = program.get('name', '')
            prog_type = program.get('type', '')
            
            # Check if this is a network accounting program
            is_target_program = False
            
            # Check exact name matches
            if prog_name in self.target_program_names:
                is_target_program = True
            
            # Check partial matches for traffic-related programs
            elif any(keyword in prog_name.lower() for keyword in ['traffic', 'accounting', 'xdp_traffic', 'tc_traffic']):
                is_target_program = True
            
            # Check by program type and context clues
            elif prog_type in ['xdp', 'sched_cls'] and any(keyword in prog_name.lower() for keyword in ['classifier', 'ingress', 'egress']):
                is_target_program = True
            
            if is_target_program:
                try:
                    result = self.run_command_silent(['bpftool', 'prog', 'delete', 'id', str(prog_id)])
                    if result.returncode == 0:
                        self.log(f"✓ Removed BPF program: {prog_name} (ID: {prog_id})")
                        self.cleaned_programs.append(f"BPF:{prog_name}:{prog_id}")
                        cleaned_any = True
                    # If program is attached and can't be deleted, try to detach first
                    else:
                        # Try various detachment methods
                        self._try_detach_program(prog_id, prog_name, prog_type)
                        # Try deleting again
                        result = self.run_command_silent(['bpftool', 'prog', 'delete', 'id', str(prog_id)])
                        if result.returncode == 0:
                            self.log(f"✓ Removed BPF program after detach: {prog_name} (ID: {prog_id})")
                            self.cleaned_programs.append(f"BPF:{prog_name}:{prog_id}")
                            cleaned_any = True
                except Exception:
                    continue
        
        if not cleaned_any and self.verbose:
            self.log("ℹ️  No network accounting BPF programs found")
        
        return cleaned_any
    
    def _try_detach_program(self, prog_id: int, prog_name: str, prog_type: str):
        """Try to detach a BPF program using various methods"""
        # Get all interfaces to try detaching from each one
        all_interfaces = self.get_all_interfaces_across_namespaces()
        
        for ns_name, interfaces in all_interfaces.items():
            for interface in interfaces:
                try:
                    if ns_name == 'host':
                        cmd_prefix = []
                    else:
                        cmd_prefix = ['ip', 'netns', 'exec', ns_name]
                    
                    # Try XDP detachment
                    if prog_type == 'xdp':
                        cmd = cmd_prefix + ['ip', 'link', 'set', interface, 'xdp', 'off']
                        self.run_command_silent(cmd)
                    
                    # Try TC detachment
                    elif prog_type == 'sched_cls':
                        # Try ingress
                        cmd = cmd_prefix + ['tc', 'filter', 'del', 'dev', interface, 'ingress']
                        self.run_command_silent(cmd)
                        # Try egress
                        cmd = cmd_prefix + ['tc', 'filter', 'del', 'dev', interface, 'egress']
                        self.run_command_silent(cmd)
                
                except Exception:
                    continue
    
    def cleanup_network_accounting_maps_comprehensive(self) -> bool:
        """Remove all network accounting BPF maps"""
        self.log("🔄 Comprehensive BPF map cleanup...")
        
        maps = self.get_all_bpf_maps()
        cleaned_any = False
        
        for bpf_map in maps:
            map_id = bpf_map.get('id')
            map_name = bpf_map.get('name', '')
            
            # Check if this is a network accounting map
            is_target_map = False
            
            # Check exact name matches
            if map_name in self.target_map_names:
                is_target_map = True
            
            # Check partial matches
            elif any(keyword in map_name.lower() for keyword in ['traffic', 'whitelist', 'accounting']):
                is_target_map = True
            
            if is_target_map:
                try:
                    result = self.run_command_silent(['bpftool', 'map', 'delete', 'id', str(map_id)])
                    if result.returncode == 0:
                        self.log(f"✓ Removed BPF map: {map_name} (ID: {map_id})")
                        self.cleaned_maps.append(f"MAP:{map_name}:{map_id}")
                        cleaned_any = True
                except Exception:
                    continue
        
        if not cleaned_any and self.verbose:
            self.log("ℹ️  No network accounting BPF maps found")
        
        return cleaned_any
    
    def force_cleanup_all_bpf_programs(self) -> bool:
        """Force cleanup of ALL BPF programs (use with extreme caution)"""
        self.log("⚠️  FORCE CLEANUP: Removing ALL BPF programs and maps...")
        self.log("This will affect all eBPF programs on the system!")
        
        cleaned_any = False
        
        # Remove all programs
        programs = self.get_all_bpf_programs()
        for program in programs:
            prog_id = program.get('id')
            try:
                result = self.run_command_silent(['bpftool', 'prog', 'delete', 'id', str(prog_id)])
                if result.returncode == 0:
                    self.log(f"✓ Force removed BPF program ID: {prog_id}")
                    cleaned_any = True
            except Exception:
                continue
        
        # Remove all maps
        maps = self.get_all_bpf_maps()
        for bpf_map in maps:
            map_id = bpf_map.get('id')
            try:
                result = self.run_command_silent(['bpftool', 'map', 'delete', 'id', str(map_id)])
                if result.returncode == 0:
                    self.log(f"✓ Force removed BPF map ID: {map_id}")
                    cleaned_any = True
            except Exception:
                continue
        
        return cleaned_any
    
    def load_multi_config(self, config_file: str) -> Dict[str, List[str]]:
        """Load multi-instance configuration and extract namespace/interface mappings"""
        try:
            if not os.path.exists(config_file):
                self.log(f"❌ Configuration file not found: {config_file}")
                return {}
            
            with open(config_file, 'r') as f:
                config = json.load(f)
            
            if "instances" not in config:
                self.log("❌ Configuration must contain 'instances' array")
                return {}
            
            # Build mapping of namespace -> interfaces
            ns_interface_map = {}
            
            for instance in config["instances"]:
                tag = instance.get("tag", "unknown")
                namespace = instance.get("namespace")  # Can be null
                interface = instance.get("interface")
                
                if not interface:
                    self.log(f"⚠️ Instance '{tag}' missing interface, skipping")
                    continue
                
                # Use 'host' for null namespace
                ns_key = namespace if namespace else 'host'
                
                if ns_key not in ns_interface_map:
                    ns_interface_map[ns_key] = []
                
                # Add interface if not already present
                if interface not in ns_interface_map[ns_key]:
                    ns_interface_map[ns_key].append(interface)
                
                self.log(f"✓ Added {interface} from namespace '{ns_key}' (instance: {tag})")
            
            self.log(f"📋 Loaded configuration with {len(config['instances'])} instances across {len(ns_interface_map)} namespaces")
            return ns_interface_map
            
        except json.JSONDecodeError as e:
            self.log(f"❌ Invalid JSON in configuration file: {e}")
            return {}
        except Exception as e:
            self.log(f"❌ Error loading configuration: {e}")
            return {}
    
    def cleanup_xdp_programs_targeted(self, target_interfaces_map: Dict[str, List[str]]) -> bool:
        """Remove XDP programs from specified interfaces in specified namespaces"""
        self.log("🔄 Targeted XDP cleanup based on configuration...")
        cleaned_any = False
        
        for ns_name, interfaces in target_interfaces_map.items():
            for interface in interfaces:
                try:
                    if ns_name == 'host':
                        # Host namespace
                        cmd = ['ip', 'link', 'set', interface, 'xdp', 'off']
                    else:
                        # Named namespace
                        cmd = ['ip', 'netns', 'exec', ns_name, 'ip', 'link', 'set', interface, 'xdp', 'off']
                    
                    result = self.run_command_silent(cmd)
                    if result.returncode == 0:
                        self.log(f"✓ Removed XDP from {interface} ({ns_name})")
                        self.cleaned_xdp_programs.append(f"XDP:{ns_name}:{interface}")
                        cleaned_any = True
                
                except Exception:
                    continue  # Best effort, continue with next interface
        
        if not cleaned_any and self.verbose:
            self.log("ℹ️  No XDP programs found to remove from specified interfaces")
        
        return cleaned_any
    
    def cleanup_tc_filters_targeted(self, target_interfaces_map: Dict[str, List[str]]) -> bool:
        """Remove TC filters from specified interfaces in specified namespaces"""
        self.log("🔄 Targeted TC cleanup based on configuration...")
        cleaned_any = False
        
        for ns_name, interfaces in target_interfaces_map.items():
            for interface in interfaces:
                try:
                    if ns_name == 'host':
                        cmd_prefix = []
                    else:
                        cmd_prefix = ['ip', 'netns', 'exec', ns_name]
                    
                    # Clean ingress filters
                    clean_cmd = cmd_prefix + ['tc', 'filter', 'del', 'dev', interface, 'ingress']
                    result = self.run_command_silent(clean_cmd)
                    if result.returncode == 0:
                        self.log(f"✓ Removed TC ingress filters from {interface} ({ns_name})")
                        self.cleaned_tc_filters.append(f"ingress:{ns_name}:{interface}")
                        cleaned_any = True
                    
                    # Clean egress filters
                    clean_cmd = cmd_prefix + ['tc', 'filter', 'del', 'dev', interface, 'egress']
                    result = self.run_command_silent(clean_cmd)
                    if result.returncode == 0:
                        self.log(f"✓ Removed TC egress filters from {interface} ({ns_name})")
                        self.cleaned_tc_filters.append(f"egress:{ns_name}:{interface}")
                        cleaned_any = True
                    
                    # Remove clsact qdisc (this will remove all associated filters)
                    clean_cmd = cmd_prefix + ['tc', 'qdisc', 'del', 'dev', interface, 'clsact']
                    result = self.run_command_silent(clean_cmd)
                    if result.returncode == 0:
                        self.log(f"✓ Removed clsact qdisc from {interface} ({ns_name})")
                        cleaned_any = True
                    
                    # Also try to remove any other TC qdiscs that might interfere
                    for qdisc_type in ['clsact', 'ingress', 'handle']:
                        clean_cmd = cmd_prefix + ['tc', 'qdisc', 'del', 'dev', interface, qdisc_type]
                        self.run_command_silent(clean_cmd)  # Best effort, ignore results
                
                except Exception:
                    continue  # Best effort, continue with next interface
        
        if not cleaned_any and self.verbose:
            self.log("ℹ️  No TC filters found to remove from specified interfaces")
        
        return cleaned_any
    
    def cleanup_all(self, target_interfaces: List[str] = None, target_namespaces: List[str] = None, 
                   force: bool = False, config_file: str = None) -> bool:
        """Perform cleanup - comprehensive or targeted based on config file"""
        
        if config_file:
            # Targeted cleanup based on configuration file
            self.log(f"🧹 Starting targeted eBPF cleanup based on config: {config_file}", force=True)
            
            target_interfaces_map = self.load_multi_config(config_file)
            if not target_interfaces_map:
                self.log("❌ No valid instances found in configuration file")
                return False
            
            total_cleaned = False
            
            # 1. Clean XDP programs from specified interfaces
            if self.cleanup_xdp_programs_targeted(target_interfaces_map):
                total_cleaned = True
            
            # 2. Clean TC filters from specified interfaces
            if self.cleanup_tc_filters_targeted(target_interfaces_map):
                total_cleaned = True
            
            # 3. Clean BPF programs (still comprehensive - programs don't have interface binding)
            if self.cleanup_network_accounting_programs_comprehensive():
                total_cleaned = True
            
            # 4. Clean BPF maps (still comprehensive - maps are global)
            if self.cleanup_network_accounting_maps_comprehensive():
                total_cleaned = True
            
            # 5. Force cleanup if requested
            if force:
                if self.force_cleanup_all_bpf_programs():
                    total_cleaned = True
            
            return total_cleaned
        
        else:
            # Comprehensive cleanup across all namespaces and interfaces
            self.log("🧹 Starting comprehensive eBPF cleanup across all namespaces...", force=True)
            
            total_cleaned = False
            
            # 1. Clean XDP programs from all interfaces
            if self.cleanup_xdp_programs_comprehensive():
                total_cleaned = True
            
            # 2. Clean TC filters from all interfaces
            if self.cleanup_tc_filters_comprehensive():
                total_cleaned = True
            
            # 3. Clean specific network accounting programs
            if self.cleanup_network_accounting_programs_comprehensive():
                total_cleaned = True
            
            # 4. Clean specific network accounting maps
            if self.cleanup_network_accounting_maps_comprehensive():
                total_cleaned = True
            
            # 5. Force cleanup if requested
            if force:
                if self.force_cleanup_all_bpf_programs():
                    total_cleaned = True
            
            return total_cleaned
    
    def verify_cleanup(self) -> bool:
        """Verify that cleanup was successful"""
        self.log("🔍 Verifying cleanup...")
        
        # Check for remaining network accounting programs
        programs = self.get_all_bpf_programs()
        remaining_programs = []
        for prog in programs:
            prog_name = prog.get('name', '')
            if (prog_name in self.target_program_names or 
                any(keyword in prog_name.lower() for keyword in ['traffic', 'accounting'])):
                remaining_programs.append(prog)
        
        # Check for remaining network accounting maps
        maps = self.get_all_bpf_maps()
        remaining_maps = []
        for map_obj in maps:
            map_name = map_obj.get('name', '')
            if map_name in self.target_map_names:
                remaining_maps.append(map_obj)
        
        if remaining_programs and self.verbose:
            self.log(f"⚠️  {len(remaining_programs)} network accounting programs still loaded")
            for prog in remaining_programs[:3]:  # Show first 3
                self.log(f"   - {prog.get('name', 'unknown')} (ID: {prog.get('id')})")
        
        if remaining_maps and self.verbose:
            self.log(f"⚠️  {len(remaining_maps)} network accounting maps still loaded")
            for map_obj in remaining_maps[:3]:  # Show first 3
                self.log(f"   - {map_obj.get('name', 'unknown')} (ID: {map_obj.get('id')})")
        
        if not remaining_programs and not remaining_maps:
            self.log("✅ All network accounting eBPF resources cleaned up successfully")
            return True
        else:
            return False
    
    def show_summary(self):
        """Show cleanup summary"""
        self.log("📊 Cleanup Summary:", force=True)
        self.log(f"XDP programs cleaned: {len(self.cleaned_xdp_programs)}", force=True)
        self.log(f"BPF programs cleaned: {len(self.cleaned_programs)}", force=True)
        self.log(f"BPF maps cleaned: {len(self.cleaned_maps)}", force=True)
        self.log(f"TC filters cleaned: {len(self.cleaned_tc_filters)}", force=True)
        
        if self.verbose:
            if self.cleaned_xdp_programs:
                self.log("\nCleaned XDP programs:")
                for prog in self.cleaned_xdp_programs:
                    self.log(f"  - {prog}")
            
            if self.cleaned_programs:
                self.log("\nCleaned BPF programs:")
                for prog in self.cleaned_programs:
                    self.log(f"  - {prog}")
            
            if self.cleaned_maps:
                self.log("\nCleaned BPF maps:")
                for map_name in self.cleaned_maps:
                    self.log(f"  - {map_name}")
            
            if self.cleaned_tc_filters:
                self.log("\nCleaned TC filters:")
                for filter_name in self.cleaned_tc_filters:
                    self.log(f"  - {filter_name}")


def main():
    """Main entry point with argument parsing"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Enhanced eBPF Network Accounting Cleanup Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                           # Clean up network accounting programs (silent)
  %(prog)s --verbose                 # Clean with detailed output
  %(prog)s --config multi_accounting_config.json  # Clean only instances from config
  %(prog)s --config multi_accounting_config.json --verbose  # Targeted cleanup with output
  %(prog)s --force                   # Force cleanup all eBPF programs
  %(prog)s --verify-only             # Only verify current state
  %(prog)s --force --verbose         # Force cleanup with detailed output

This enhanced version:
- Cleans eBPF programs across ALL namespaces and interfaces (default)
- Can target specific namespaces/interfaces from config file (--config)
- Uses best-effort approach with minimal error output
- Targets specific network accounting programs and maps
- Includes comprehensive XDP and TC filter cleanup

Configuration file format:
{
  "instances": [
    {
      "tag": "gbb",
      "namespace": "gbb",
      "interface": "data-apn",
      "tc_ingress": true
    },
    {
      "tag": "host-instance", 
      "namespace": null,
      "interface": "eth0",
      "tc_ingress": true
    }
  ]
}
        """
    )
    
    parser.add_argument('--config', '-c', type=str,
                       help='Multi-instance configuration file (clean only specified namespaces/interfaces)')
    parser.add_argument('--force', '-f', action='store_true',
                       help='Force cleanup of ALL eBPF programs and maps (dangerous)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output - show detailed cleanup information')
    parser.add_argument('--verify-only', action='store_true',
                       help='Only verify current state, do not clean')
    
    args = parser.parse_args()
    
    # Check if running as root
    if os.geteuid() != 0:
        print("❌ This script requires root privileges.")
        print(f"Please run: sudo python3 {sys.argv[0]}")
        sys.exit(1)
    
    # Create cleanup tool
    cleanup_tool = EnhancedBPFCleanupTool(verbose=args.verbose)
    
    if args.verify_only:
        # Only verify current state
        cleanup_tool.verify_cleanup()
        sys.exit(0)
    
    # Perform cleanup
    success = cleanup_tool.cleanup_all(force=args.force, config_file=args.config)
    
    # Verify cleanup
    verification_success = cleanup_tool.verify_cleanup()
    
    # Show summary
    cleanup_tool.show_summary()
    
    if success or verification_success:
        print("\n✅ Cleanup completed successfully!")
        print("You can now run the network accounting program again.")
    else:
        print("\n⚠️  No eBPF resources were found to clean up.")
        print("The system should be ready to run the network accounting program.")
    
    sys.exit(0)


if __name__ == "__main__":
    main()
