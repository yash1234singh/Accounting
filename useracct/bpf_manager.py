#!/usr/bin/env python3

import os
import subprocess
from typing import Optional, List, Dict
from bcc import BPF
from typing import Optional, List, Dict 

class BPFProgramManager:
    """Manages eBPF program loading, compilation, and lifecycle"""
    
    def __init__(self, interface: str, namespace: Optional[str] = None, use_tc_ingress: bool = False, debug: bool = False, object_file: str = None, tag: str = None):

        self.interface = interface
        self.namespace = namespace
        self.use_tc_ingress = use_tc_ingress
        self.debug = debug
        self.tag = tag
        
        # Resolve object file path
        if object_file is None:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(script_dir)
            self.object_file = os.path.join(project_root, "build", "objects", "network_accounting.bpf.o")
        else:
            if not os.path.isabs(object_file):
                script_dir = os.path.dirname(os.path.abspath(__file__))
                project_root = os.path.dirname(script_dir)
                self.object_file = os.path.join(project_root, object_file)
            else:
                self.object_file = object_file
        
        # BPF components
        self.bpf = None
        self.traffic_map_a_rx = None
        self.traffic_map_b_rx = None
        self.traffic_map_a_tx = None
        self.traffic_map_b_tx = None
        self.active_buffer_map = None
        self.whitelist_map = None
        
        # Track loaded functions
        self.xdp_fn = None
        self.tc_ingress_fn = None
        self.tc_egress_fn = None
        self.current_active_buffer = 0

        # Map naming based on tag (prioritize tag over object file)
        if tag:
            # Use the tag directly (should be short like "bd", "gbb")
            self.traffic_map_a_rx_name = f"t_m_a_r_{tag}"   # RX Buffer A
            self.traffic_map_b_rx_name = f"t_m_b_r_{tag}"   # RX Buffer B
            self.traffic_map_a_tx_name = f"t_m_a_t_{tag}"   # TX Buffer A
            self.traffic_map_b_tx_name = f"t_m_b_t_{tag}"   # TX Buffer B
            self.active_buffer_map_rx_name = f"a_buf_r_{tag}"  # RX active buffer control
            self.active_buffer_map_tx_name = f"a_buf_t_{tag}"  # TX active buffer control
            self.whitelist_map_rx_name = f"w_m_r_{tag}"      # RX whitelist
            self.whitelist_map_tx_name = f"w_m_t_{tag}"      # TX whitelist
        else:
            # Default case
            self.traffic_map_a_rx_name = "t_m_a_r"
            self.traffic_map_b_rx_name = "t_m_b_r"
            self.traffic_map_a_tx_name = "t_m_a_t"
            self.traffic_map_b_tx_name = "t_m_b_t"
            self.active_buffer_map_rx_name = "a_buf_r"       # RX active buffer control
            self.active_buffer_map_tx_name = "a_buf_t"       # TX active buffer control
            self.whitelist_map_rx_name = "w_m_r"             # RX whitelist
            self.whitelist_map_tx_name = "w_m_t"             # TX whitelist


    def load_functions(self) -> bool:
        """Initialize BPF maps and prepare for program attachment
        
        Both XDP and TC modes now try pre-compiled objects first, fallback to BCC only if needed
        """
        try:
            if self.debug:
                print("Initializing BPF program...")
            
            # Try pre-compiled object file first (for both XDP and TC modes)
            script_dir = os.path.dirname(os.path.abspath(__file__))
            
            # Try multiple paths for the object file
            possible_paths = [
                self.object_file,  # Direct path
                os.path.join(script_dir, self.object_file),  # Script directory
                os.path.join(os.getcwd(), self.object_file),  # Current working directory
                os.path.abspath(self.object_file)  # Absolute path
            ]

            self.obj_path = None
            for path in possible_paths:
                if os.path.exists(path):
                    self.obj_path = path
                    break

            # If pre-compiled object exists, use it for both XDP and TC
            if self.obj_path:
                mode_name = "XDP" if not self.use_tc_ingress else "TC"
                print(f"{mode_name} mode: Using pre-compiled object file")
                
                if self.debug:
                    print(f"✓ Found object file: {self.obj_path}")
                    print(f"✓ Using double buffer RX/TX maps:")
                    print(f"   RX: {self.traffic_map_a_rx_name}, {self.traffic_map_b_rx_name}")
                    print(f"   TX: {self.traffic_map_a_tx_name}, {self.traffic_map_b_tx_name}")
                    print(f"   Control RX: {self.active_buffer_map_rx_name}, Control TX: {self.active_buffer_map_tx_name}")
                    print(f"   Whitelist RX: {self.whitelist_map_rx_name}, Whitelist TX: {self.whitelist_map_tx_name}")
                
                # Set section references for program attachment
                if self.use_tc_ingress:
                    self.tc_ingress_fn = "classifier/ingress"
                    self.tc_egress_fn = "classifier/egress"
                else:
                    self.xdp_fn = "xdp"  # XDP section name
                    self.tc_egress_fn = "classifier/egress"  # Still need TC for egress
                
                # Maps will be accessed later via get_kernel_maps()
                self.traffic_map_a = None
                self.traffic_map_b = None
                self.active_buffer_map = None
                self.whitelist_map = None
                
                return True
            
            # Fallback to BCC only if no pre-compiled object exists
            else:
                print("❌ Could not find pre-compiled object file")
                print(f"   Searched in:")
                for path in possible_paths:
                    print(f"     - {path}")
                print(f"   Current working directory: {os.getcwd()}")
                print(f"   Script directory: {script_dir}")
                
                # Only use BCC as absolute last resort for development
                if not self.use_tc_ingress:
                    print("XDP mode: Falling back to BCC (development only)")
                    
                    # Try to load with BCC for development
                    script_dir = os.path.dirname(os.path.abspath(__file__))
                    project_root = os.path.dirname(script_dir)
                    bcc_src_file = os.path.join(project_root, "ebpf", "bpf_program.py")
                    
                    if os.path.exists(bcc_src_file):
                        try:
                            # Import BCC development module
                            import sys
                            sys.path.append(os.path.join(project_root, "ebpf"))
                            from bpf_program import create_dynamic_accounting
                            
                            # Create BCC-based accounting
                            self.bcc_accounting = create_dynamic_accounting(
                                interface=self.interface,
                                use_xdp=True,
                                debug=self.debug
                            )
                            
                            if self.bcc_accounting.load_program():
                                print("✓ BCC fallback loaded successfully")
                                self.bpf = self.bcc_accounting.bpf
                                self.traffic_map_a = self.bpf["traffic_map"]
                                self.whitelist_map = self.bpf["whitelist_map"]
                                self.xdp_fn = self.bpf.load_func("xdp_traffic_accounting", BPF.XDP)
                                self.tc_egress_fn = self.bpf.load_func("tc_traffic_eg", BPF.SCHED_CLS)
                                return True
                            else:
                                print("❌ BCC fallback failed")
                                return False
                                
                        except Exception as e:
                            print(f"❌ BCC fallback error: {e}")
                            return False
                    else:
                        print(f"❌ BCC source file not found: {bcc_src_file}")
                        return False
                else:
                    print("❌ TC mode requires pre-compiled objects - run 'make all' first")
                    return False
                
        except Exception as e:
            print(f"Error loading BPF functions: {e}")
            import traceback
            traceback.print_exc()
            return False

    def get_kernel_maps(self):
        """Get BPF maps from kernel with separate RX/TX control maps"""
        try:
            # If using BCC fallback (no obj_path), return BCC maps
            if not self.obj_path:
                return self.traffic_map_a_rx, self.whitelist_map
            
            if self.debug:
                print("Getting kernel-managed BPF maps with separate RX/TX control maps...")
                print(f"🔍 Tag parameter: '{self.tag}'")
            
            import subprocess
            import json
            
            result = subprocess.run(['bpftool', 'map', 'list', '-j'], 
                                capture_output=True, text=True)
            
            if result.returncode != 0:
                print("❌ Failed to list BPF maps")
                return None, None
            
            maps = json.loads(result.stdout)
            
            # Determine effective tag for map naming
            # Priority: constructor tag > object filename tag
            effective_tag = None
            
            if self.tag:
                effective_tag = self.tag
                if self.debug:
                    print(f"Using constructor tag: '{effective_tag}'")
            elif self.obj_path and '_' in os.path.basename(self.obj_path):
                # Extract tag from filename like network_accounting_bd.bpf.o -> bd
                parts = os.path.basename(self.obj_path).split('_')
                if len(parts) >= 3:
                    obj_file_tag = parts[-1].split('.')[0]
                    effective_tag = obj_file_tag
                    if self.debug:
                        print(f"Detected tag '{effective_tag}' from object file name")
            
            if self.debug:
                print(f"🔍 Effective tag for map lookup: '{effective_tag}'")
            
            # Build expected map name patterns - SAME for both XDP and TC modes
            if effective_tag:
                expected_patterns = {
                    'rx_a': f"t_m_a_r_{effective_tag}",
                    'rx_b': f"t_m_b_r_{effective_tag}", 
                    'tx_a': f"t_m_a_t_{effective_tag}",
                    'tx_b': f"t_m_b_t_{effective_tag}",
                    'active_rx': f"a_buf_r_{effective_tag}",      # RX active buffer
                    'active_tx': f"a_buf_t_{effective_tag}",      # TX active buffer
                    'whitelist_rx': f"w_m_r_{effective_tag}",     # RX whitelist
                    'whitelist_tx': f"w_m_t_{effective_tag}"      # TX whitelist
                }
            else:
                expected_patterns = {
                    'rx_a': "t_m_a_r",
                    'rx_b': "t_m_b_r",
                    'tx_a': "t_m_a_t", 
                    'tx_b': "t_m_b_t",
                    'active_rx': "a_buf_r",      # RX active buffer
                    'active_tx': "a_buf_t",      # TX active buffer
                    'whitelist_rx': "w_m_r",     # RX whitelist
                    'whitelist_tx': "w_m_t"      # TX whitelist
                }
            
            if self.debug:
                print(f"🔍 Looking for maps with patterns: {expected_patterns}")
            
            # Find maps by name matching
            map_ids = {}
            
            if self.debug:
                print(f"🔍 Available maps in kernel:")
                for map_info in maps:
                    map_name = map_info.get('name', '')
                    map_id = map_info.get('id')
                    if any(pattern in map_name for pattern in ['t_m_', 'a_buf', 'w_m_']):
                        print(f"   {map_name} (ID: {map_id})")
            
            for map_info in maps:
                map_name = map_info.get('name', '')
                map_id = map_info.get('id')
                
                # First try exact matches
                for pattern_key, pattern_name in expected_patterns.items():
                    if map_name == pattern_name and pattern_key not in map_ids:
                        map_ids[pattern_key] = map_id
                        if self.debug:
                            print(f"✅ Exact match {pattern_key}: {map_name} (ID: {map_id})")
                
            # If we have missing maps, try flexible pattern matching
            missing_keys = [key for key in expected_patterns.keys() if key not in map_ids]
            if missing_keys and self.debug:
                print(f"🔍 Missing keys after exact match: {missing_keys}")
            
            # Fallback pattern matching for missing keys
            if missing_keys:
                for map_info in maps:
                    map_name = map_info.get('name', '')
                    map_id = map_info.get('id')
                    
                    for pattern_key in missing_keys[:]:  # Use slice to avoid modifying during iteration
                        # Try different matching strategies
                        matched = False
                        
                        # Strategy 1: If we expect tagged maps but don't have effective_tag, 
                        # try to match any map with the base pattern + any suffix
                        if not effective_tag:
                            base_patterns = {
                                'rx_a': 't_m_a_r',
                                'rx_b': 't_m_b_r', 
                                'tx_a': 't_m_a_t',
                                'tx_b': 't_m_b_t',
                                'active_rx': 'a_buf_r',
                                'active_tx': 'a_buf_t',
                                'whitelist_rx': 'w_m_r',
                                'whitelist_tx': 'w_m_t'
                            }
                            
                            base_pattern = base_patterns.get(pattern_key, '')
                            if base_pattern and (map_name == base_pattern or map_name.startswith(base_pattern + '_')):
                                map_ids[pattern_key] = map_id
                                missing_keys.remove(pattern_key)
                                matched = True
                                if self.debug:
                                    print(f"✅ Flexible match {pattern_key}: {map_name} (ID: {map_id})")
                        
                        # Strategy 2: If we have effective_tag but exact match failed,
                        # the tag might be slightly different
                        elif effective_tag and not matched:
                            # Try matching with different tag formats
                            pattern_base = expected_patterns[pattern_key].rsplit('_', 1)[0]  # Remove tag suffix
                            if map_name.startswith(pattern_base + '_'):
                                map_ids[pattern_key] = map_id
                                missing_keys.remove(pattern_key)
                                matched = True
                                if self.debug:
                                    print(f"✅ Tag flexible match {pattern_key}: {map_name} (ID: {map_id})")
            
            # Check if we found all required maps
            required_maps = ['rx_a', 'rx_b', 'tx_a', 'tx_b', 'active_rx', 'active_tx', 'whitelist_rx', 'whitelist_tx']
            missing_maps = [req for req in required_maps if req not in map_ids]
            
            if missing_maps:
                print(f"❌ Missing required maps: {missing_maps}")
                if self.debug:
                    print(f"Found maps: {list(map_ids.keys())}")
                return None, None
            
            if self.debug:
                print(f"✓ Found all required separate RX/TX control maps")
            
            # Create map wrappers
            self.traffic_map_a_rx = KernelMapWrapper(expected_patterns['rx_a'], map_ids['rx_a'], debug=self.debug)
            self.traffic_map_b_rx = KernelMapWrapper(expected_patterns['rx_b'], map_ids['rx_b'], debug=self.debug)
            self.traffic_map_a_tx = KernelMapWrapper(expected_patterns['tx_a'], map_ids['tx_a'], debug=self.debug)
            self.traffic_map_b_tx = KernelMapWrapper(expected_patterns['tx_b'], map_ids['tx_b'], debug=self.debug)
            
            # Separate control maps for RX and TX
            self.active_buffer_map_rx = KernelMapWrapper(expected_patterns['active_rx'], map_ids['active_rx'], debug=self.debug)
            self.active_buffer_map_tx = KernelMapWrapper(expected_patterns['active_tx'], map_ids['active_tx'], debug=self.debug)
            
            # Separate whitelist maps for RX and TX
            self.whitelist_map_rx = KernelMapWrapper(expected_patterns['whitelist_rx'], map_ids['whitelist_rx'], debug=self.debug)
            self.whitelist_map_tx = KernelMapWrapper(expected_patterns['whitelist_tx'], map_ids['whitelist_tx'], debug=self.debug)
            
            # Initialize both active buffers to 0 (A buffers)
            try:
                self._set_active_buffer_rx(0)
                self._set_active_buffer_tx(0)
                if self.debug:
                    print(f"🔄 Initialized both RX and TX active buffers to A")
            except Exception as e:
                if self.debug:
                    print(f"Warning: Could not initialize active buffers: {e}")
            
            # Create enhanced double buffer wrapper
            double_buffer_map = DoubleBufferRXTXMapWrapper(
                self.traffic_map_a_rx, self.traffic_map_b_rx,
                self.traffic_map_a_tx, self.traffic_map_b_tx,
                self.active_buffer_map_rx, self.active_buffer_map_tx,
                debug=self.debug
            )
            
            
            combined_whitelist = CombinedWhitelistWrapper(
                self.whitelist_map_rx, self.whitelist_map_tx, debug=self.debug
            )
            
            return double_buffer_map, combined_whitelist
                
        except Exception as e:
            print(f"Error accessing kernel maps: {e}")
            return None, None

    def _set_active_buffer_rx(self, buffer_id):
        """Set which RX buffer is active (0=A, 1=B)"""
        try:
            if self.active_buffer_map_rx:
                import ctypes
                key = ctypes.c_uint32(0)
                value = ctypes.c_uint32(buffer_id)
                self.active_buffer_map_rx[key] = value
                if self.debug:
                    buffer_name = "A" if buffer_id == 0 else "B"
                    print(f"🔄 Set RX active buffer to {buffer_name}")
        except Exception as e:
            if self.debug:
                print(f"Error setting RX active buffer: {e}")

    def _set_active_buffer_tx(self, buffer_id):
        """Set which TX buffer is active (0=A, 1=B)"""
        try:
            if self.active_buffer_map_tx:
                import ctypes
                key = ctypes.c_uint32(0)
                value = ctypes.c_uint32(buffer_id)
                self.active_buffer_map_tx[key] = value
                if self.debug:
                    buffer_name = "A" if buffer_id == 0 else "B"
                    print(f"🔄 Set TX active buffer to {buffer_name}")
        except Exception as e:
            if self.debug:
                print(f"Error setting TX active buffer: {e}")

    def _maps_match(self, found_name: str, expected_name: str, prefix: str) -> bool:
        """Check if found map name matches expected name with fuzzy logic for truncation"""
        # Exact match
        if found_name == expected_name:
            return True
        
        # Both start with expected prefix
        if not (found_name.startswith(prefix) and expected_name.startswith(prefix)):
            return False
        
        # Handle active buffer map matching
        if prefix == "a_buf":
            # Match any map that starts with "a_buf" - it could be "a_buf" or "a_buf_gbb"
            return found_name.startswith("a_buf")
        
        # Handle whitelist map matching  
        if prefix == "w_m":
            # Match any map that starts with "w_m" - it could be "w_m" or "w_m_gbb"
            return found_name.startswith("w_m")
        
        # For traffic maps (t_m_a, t_m_b), check buffer type and direction
        if prefix in ["t_m_a", "t_m_b"]:
            # Extract buffer type (a or b) from prefix
            buffer_type = prefix.split('_')[2]  # 'a' or 'b'
            
            # Check if found name contains the buffer type
            if f"t_m_{buffer_type}" not in found_name:
                return False
            
            # Extract direction from expected name
            expected_direction = ""
            if expected_name.endswith("_r"):
                expected_direction = "_r"
            elif expected_name.endswith("_t"):
                expected_direction = "_t"
            
            # Check if found name has the same direction
            if expected_direction:
                return expected_direction in found_name
            
            return True
        
        # Fallback: check if found name starts with expected prefix
        return found_name.startswith(prefix)
    
    def get_kernel_maps_libbpf(self):
        """Not used in code but keeping in handly for other env"""
        """Get BPF maps using libbpf Python bindings"""
        try:
            from bcc import libbpf  # or import pylibbpf
            
            # Find maps by name
            traffic_map = libbpf.bpf_object__find_map_by_name("traffic_map")
            whitelist_map = libbpf.bpf_object__find_map_by_name("whitelist_map")
            
            return traffic_map, whitelist_map
        except Exception as e:
            print(f"Error with libbpf: {e}")
            return None, None

    def get_maps(self):
        """Get BPF map references"""
        if self.obj_path:
            # For pre-compiled objects (both XDP and TC), use kernel maps
            return self.get_kernel_maps()
        else:
            # For BCC fallback mode, return already loaded maps
            return self.traffic_map_a, self.whitelist_map
           

    def _set_active_buffer(self, buffer_id):
        """Set which buffer is active (0=A, 1=B)"""
        try:
            if self.active_buffer_map:
                import ctypes
                key = ctypes.c_uint32(0)
                value = ctypes.c_uint32(buffer_id)
                self.active_buffer_map[key] = value
                self.current_active_buffer = buffer_id
                if self.debug:
                    buffer_name = "A" if buffer_id == 0 else "B"
                    print(f"🔄 Set active buffer to {buffer_name} (value={buffer_id})")
                    
                    # Verify the setting worked
                    try:
                        items = list(self.active_buffer_map.items())
                        if items:
                            stored_key, stored_value = items[0]
                            stored_val = getattr(stored_value, 'value', stored_value)
                            print(f"🔄 Verified active buffer setting: {stored_val}")
                        else:
                            print("🔄 Warning: Active buffer map empty after setting")
                    except Exception as e:
                        print(f"🔄 Warning: Could not verify active buffer setting: {e}")
            else:
                # Fallback - just track locally
                self.current_active_buffer = buffer_id
                if self.debug:
                    buffer_name = "A" if buffer_id == 0 else "B" 
                    print(f"🔄 Set local active buffer to {buffer_name} (no map available)")
        except Exception as e:
            if self.debug:
                print(f"Error setting active buffer: {e}")
            # Fallback - just track locally
            self.current_active_buffer = buffer_id

    def switch_buffer(self):
        """Switch to the other buffer"""
        new_buffer = 1 if self.current_active_buffer == 0 else 0
        self._set_active_buffer(new_buffer)
        return new_buffer

    def get_inactive_buffer(self):
        """Get the currently inactive buffer map"""
        if self.current_active_buffer == 0:
            return self.traffic_map_b
        else:
            return self.traffic_map_a

    def get_active_buffer(self):
        """Get the currently active buffer map"""
        if self.current_active_buffer == 0:
            return self.traffic_map_a
        else:
            return self.traffic_map_b

    def debug_map_contents(self):
        """Debug function to check all map contents"""
        if not self.debug:
            return
        
        try:
            print("🔍 === MAP DEBUGGING ===")
            
            # Check active buffer
            if hasattr(self, 'active_buffer_map') and self.active_buffer_map:
                try:
                    # Use the items() method to read the active buffer value
                    items = list(self.active_buffer_map.items())
                    if items:
                        key, value = items[0]
                        active_val = getattr(value, 'value', value)
                        print(f"🔍 Active buffer: {active_val}")
                    else:
                        print("🔍 Active buffer: NOT SET (no entries)")
                except Exception as e:
                    print(f"🔍 Active buffer: ERROR reading - {e}")
            
            # Check all traffic maps if available - FIXED: Use actual map IDs from kernel
            for map_name, map_obj in [
                ("RX_A", getattr(self, 'traffic_map_a_rx', None)),
                ("RX_B", getattr(self, 'traffic_map_b_rx', None)),
                ("TX_A", getattr(self, 'traffic_map_a_tx', None)),
                ("TX_B", getattr(self, 'traffic_map_b_tx', None))
            ]:
                if map_obj:
                    try:
                        items = list(map_obj.items())
                        print(f"🔍 {map_name} (ID {map_obj.map_id}): {len(items)} entries")
                        # Show first 3 entries if they exist
                        for i, (key, stats) in enumerate(items[:3]):
                            try:
                                src_ip = getattr(key, 'src_ip', getattr(key, 'value', 'unknown'))
                                dst_ip = getattr(key, 'dst_ip', getattr(stats, 'dst_ip', 'unknown'))
                                
                                # Convert IP integers to readable format if they're numeric
                                if isinstance(src_ip, int):
                                    import ipaddress
                                    src_ip = str(ipaddress.IPv4Address(src_ip))
                                if isinstance(dst_ip, int):
                                    import ipaddress  
                                    dst_ip = str(ipaddress.IPv4Address(dst_ip))
                                    
                                print(f"🔍 {map_name} Entry {i}: {src_ip}->{dst_ip} RX={stats.rx_bytes}, TX={stats.tx_bytes}")
                            except Exception as e:
                                print(f"🔍 {map_name} Entry {i}: Error parsing - {e}")
                    except Exception as e:
                        print(f"🔍 {map_name}: ERROR - {e}")
                            
        except Exception as e:
            print(f"🔍 Map debugging failed: {e}")
    
    def _print_map_details(self):
        """Print detailed information about all BPF maps"""
        try:
            print("\n🗺️ BPF MAP DETAILS:")
            print("-" * 50)
            
            # Track if we've shown at least one map
            maps_shown = False
            
            # Try to access all maps - works in newer BCC versions
            if hasattr(self.bpf, 'maps') and self.bpf.maps:
                print("All detected BPF maps:")
                # Detailed info for all maps
                for name, bpf_map in self.bpf.maps.items():
                    map_id = bpf_map.map_id if hasattr(bpf_map, 'map_id') else 'unknown'
                    map_fd = bpf_map.get_fd() if hasattr(bpf_map, 'get_fd') else 'unknown'
                    map_type = getattr(bpf_map, 'type', 'unknown')
                    map_max_entries = getattr(bpf_map, 'max_entries', 'unknown')
                    
                    print(f"Map Name: {name}")
                    print(f"  - ID: {map_id}")
                    print(f"  - FD: {map_fd}")
                    print(f"  - Type: {map_type}")
                    print(f"  - Max Entries: {map_max_entries}")
                    maps_shown = True
            
            # Always show our tracked maps, even if we already showed all maps
            print("\nDirectly accessed maps:")
            
            # Show traffic_map details (guaranteed to work in all BCC versions)
            if self.traffic_map:
                map_id = self.traffic_map.map_id if hasattr(self.traffic_map, 'map_id') else 'unknown'
                map_fd = self.traffic_map.map_fd if hasattr(self.traffic_map, 'map_fd') else 'unknown'
                map_name = self.traffic_map.name if hasattr(self.traffic_map, 'name') else 'traffic_map'
                
                print(f"Map: {map_name}")
                print(f"  - ID: {map_id}")
                print(f"  - FD: {map_fd}")
                print(f"  - Contains traffic statistics for network hosts")
                maps_shown = True
            
            # Show whitelist_map details
            if self.whitelist_map:
                map_id = self.whitelist_map.map_id if hasattr(self.whitelist_map, 'map_id') else 'unknown'
                map_fd = self.whitelist_map.map_fd if hasattr(self.whitelist_map, 'map_fd') else 'unknown'
                map_name = self.whitelist_map.name if hasattr(self.whitelist_map, 'name') else 'whitelist_map'
                
                print(f"Map: {map_name}")
                print(f"  - ID: {map_id}")
                print(f"  - FD: {map_fd}")
                print(f"  - Contains whitelisted IP addresses")
                maps_shown = True
                
            if not maps_shown:
                print("No maps could be detected in the BPF program.")
                
            # Try to access raw tables directly as additional fallback
            try:
                table_ids = []
                if hasattr(self.bpf, 'get_table_offline_info'):
                    print("\nRaw BPF tables information:")
                    tables_info = self.bpf.get_table_offline_info()
                    for table_name, table_info in tables_info.items():
                        if hasattr(table_info, 'id'):
                            print(f"Table: {table_name}, ID: {table_info.id}")
                            table_ids.append(table_info.id)
                            maps_shown = True
                    
                # Last resort - use bpftool to list maps
                if not maps_shown:
                    import subprocess
                    print("\nAttempting to use bpftool to list maps...")
                    try:
                        result = subprocess.run(['bpftool', 'map', 'list'], capture_output=True, text=True)
                        if result.returncode == 0:
                            print("bpftool output:")
                            print(result.stdout)
                            maps_shown = True
                    except Exception as e:
                        print(f"bpftool error: {e}")
            except Exception as e:
                print(f"Error accessing raw tables: {e}")
            
            print("-" * 50)
        except Exception as e:
            print(f"Error printing map details: {e}")
            # Fallback to minimal info
            if self.traffic_map:
                map_id = self.traffic_map.map_id if hasattr(self.traffic_map, 'map_id') else 'unknown'
                print(f"Map: traffic_map       ID: {map_id}")
            
            if self.whitelist_map:
                map_id = self.whitelist_map.map_id if hasattr(self.whitelist_map, 'map_id') else 'unknown'
                print(f"Map: whitelist_map     ID: {map_id}")
                
            print("-" * 50)

class KernelMapWrapper:
    """Wrapper for kernel-managed BPF maps accessed via bpftool"""
    
    def __init__(self, name: str, map_id: int, debug: bool = False):
        self.name = name
        self.map_id = map_id
        self.debug = debug
    
    def __setitem__(self, key, value):
        """Update map entry using bpftool"""
        import subprocess
        import struct
        
        # Convert key to bytes based on the actual key structure
        try:
            if hasattr(key, 'src_ip') and hasattr(key, 'dst_ip') and hasattr(key, 'protocol'):
                # Flow key format: src_ip(4), dst_ip(4), protocol(1), padding(3) = 12 bytes
                key_bytes = struct.pack('<II', key.src_ip, key.dst_ip) + bytes([key.protocol, 0, 0, 0])
            elif hasattr(key, 'value'):
                # Old format: just IP address (4 bytes) - pad to 12 bytes if needed
                if 't_m_' in self.name:
                    # For traffic maps, pad to 12 bytes
                    key_bytes = struct.pack('<I', key.value) + bytes([0, 0, 0, 0, 0, 0, 0, 0])
                else:
                    # For whitelist maps and active_buffer_map, use 4 bytes
                    key_bytes = struct.pack('<I', key.value)
            else:
                # Fallback: treat as integer
                if 't_m_' in self.name:
                    key_bytes = struct.pack('<I', int(key)) + bytes([0, 0, 0, 0, 0, 0, 0, 0])
                elif 'a_buf' in self.name:
                    # Active buffer map uses 4-byte key
                    key_bytes = struct.pack('<I', int(key))
                else:
                    key_bytes = struct.pack('<I', int(key))
        except Exception as e:
            if self.debug:
                print(f"❌ Key conversion failed: {e}")
            raise Exception(f"Key conversion failed: {e}")
        
        # Convert value to bytes based on map type and value structure
        try:
            if self.name.endswith('whitelist_map') or 'w_m' in self.name:
                # Whitelist entry: just exists flag (1 byte)
                if hasattr(value, 'exists'):
                    value_bytes = bytes([value.exists])
                else:
                    value_bytes = bytes([1])  # Default exists = 1
            elif 'active_buffer' in self.name or 'a_buf' in self.name:
                # Active buffer map: just the buffer ID (4 bytes for u32)
                if hasattr(value, 'value'):
                    value_bytes = struct.pack('<I', value.value)
                else:
                    value_bytes = struct.pack('<I', int(value))
            else:
                # Traffic stats entry: rx_bytes(8), tx_bytes(8), dst_ip(4), protocol(1), padding(3) = 24 bytes
                rx_bytes = getattr(value, 'rx_bytes', 0)
                tx_bytes = getattr(value, 'tx_bytes', 0)
                dst_ip = getattr(value, 'dst_ip', 0)
                protocol = getattr(value, 'protocol', 0)
                
                # Pack as: rx_bytes(8), tx_bytes(8), dst_ip(4), protocol(1), padding(3)
                value_bytes = struct.pack('<QQIBxxx', rx_bytes, tx_bytes, dst_ip, protocol)
        except Exception as e:
            if self.debug:
                print(f"❌ Value conversion failed: {e}")
            raise Exception(f"Value conversion failed: {e}")
        
        # Use Format 2: space-separated hex bytes (known to work)
        key_hex_list = [f'0x{b:02x}' for b in key_bytes]
        value_hex_list = [f'0x{b:02x}' for b in value_bytes]
        
        cmd = ['bpftool', 'map', 'update', 'id', str(self.map_id), 
            'key'] + key_hex_list + ['value'] + value_hex_list
        
        if self.debug:
            print(f"🔧 bpftool update: key({len(key_bytes)} bytes) value({len(value_bytes)} bytes)")
            if 'active_buffer' in self.name:
                print(f"🔧 Active buffer update: setting to {int(value) if not hasattr(value, 'value') else value.value}")
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            error_msg = result.stderr.strip() if result.stderr else "Unknown error"
            if self.debug:
                print(f"❌ bpftool update failed: {error_msg}")
                print(f"❌ Command: {' '.join(cmd)}")
            raise Exception(f"Failed to update map: {error_msg}")
        
        if self.debug:
            print(f"✅ Successfully updated map entry")

    def items(self):
        """Iterate over map entries using bpftool"""
        import subprocess
        import json
        import struct
        
        result = subprocess.run(['bpftool', 'map', 'dump', 'id', str(self.map_id), '-j'],
                            capture_output=True, text=True)
        
        if result.returncode != 0:
            if self.debug:
                print(f"❌ bpftool dump failed for map {self.map_id}: {result.stderr}")
            return []
        
        try:
            entries = json.loads(result.stdout)
            if self.debug:
                print(f"📊 Map {self.name} (ID {self.map_id}) raw entries: {len(entries)}")
            
            # Convert to format expected by stats collector
            for i, entry in enumerate(entries):
                try:
                    # Parse key - handle hex array format
                    key_data = entry.get('key', [])
                    if not key_data or not isinstance(key_data, list):
                        if self.debug:
                            print(f"⚠️ Entry {i}: No key data or wrong format")
                        continue
                    
                    # Convert hex array to bytes
                    try:
                        key_bytes = bytes([int(x, 16) for x in key_data])
                    except (ValueError, TypeError) as e:
                        if self.debug:
                            print(f"⚠️ Entry {i}: Failed to convert key hex: {e}")
                        continue
                    
                    if self.debug and i < 3:
                        print(f"🔍 Entry {i}: Key bytes length: {len(key_bytes)}, hex: {key_bytes.hex()}")
                    
                    # Parse flow key: src_ip(4), dst_ip(4), protocol(1), padding(3) = 12 bytes
                    if len(key_bytes) >= 12:
                        # Unpack src_ip and dst_ip (little endian)
                        src_ip, dst_ip = struct.unpack('<II', key_bytes[:8])
                        # Protocol is at byte 8
                        protocol = key_bytes[8] if len(key_bytes) > 8 else 0
                        
                        if self.debug and i < 3:
                            print(f"🔍 Entry {i}: Parsed flow key - src_ip: {src_ip}, dst_ip: {dst_ip}, protocol: {protocol}")
                    elif len(key_bytes) >= 4:
                        # Fallback for old format (just IP address)
                        src_ip = struct.unpack('<I', key_bytes[:4])[0]
                        dst_ip = 0  # Will be taken from value
                        protocol = 0
                        
                        if self.debug and i < 3:
                            print(f"🔍 Entry {i}: Parsed old key format - src_ip: {src_ip}")
                    else:
                        if self.debug:
                            print(f"⚠️ Entry {i}: Key too short: {len(key_bytes)} bytes")
                        continue
                    
                    # Parse value - handle hex array format
                    value_data = entry.get('value', [])
                    if not value_data or not isinstance(value_data, list):
                        if self.debug:
                            print(f"⚠️ Entry {i}: No value data or wrong format")
                        continue
                    
                    # Convert hex array to bytes
                    try:
                        value_bytes = bytes([int(x, 16) for x in value_data])
                    except (ValueError, TypeError) as e:
                        if self.debug:
                            print(f"⚠️ Entry {i}: Failed to convert value hex: {e}")
                        continue
                    
                    if self.debug and i < 3:
                        print(f"🔍 Entry {i}: Value bytes length: {len(value_bytes)}, hex: {value_bytes.hex()}")
                    
                    # Parse value: traffic_stats structure
                    # rx_bytes(8), tx_bytes(8), dst_ip(4), protocol(1), padding(3) = 24 bytes
                    if len(value_bytes) >= 20:
                        rx_bytes, tx_bytes, dst_ip_val = struct.unpack('<QQI', value_bytes[:20])
                        protocol_val = value_bytes[20] if len(value_bytes) > 20 else protocol
                        
                        if self.debug and i < 3:
                            print(f"🔍 Entry {i}: Parsed stats - rx: {rx_bytes}, tx: {tx_bytes}, dst_ip_val: {dst_ip_val}, protocol_val: {protocol_val}")
                        
                        # Use dst_ip from value if not in key (backward compatibility)
                        if dst_ip == 0:
                            dst_ip = dst_ip_val
                        
                        # Create wrapper objects for compatibility
                        class TrafficStats:
                            def __init__(self, rx, tx, dst, proto):
                                self.rx_bytes = rx
                                self.tx_bytes = tx
                                self.dst_ip = dst
                                self.protocol = proto
                        
                        class FlowKeyWrapper:
                            def __init__(self, src_ip, dst_ip, proto):
                                self.src_ip = src_ip
                                self.dst_ip = dst_ip 
                                self.protocol = proto
                                # For backward compatibility with existing code
                                self.value = src_ip
                        
                        yield (FlowKeyWrapper(src_ip, dst_ip, protocol), 
                            TrafficStats(rx_bytes, tx_bytes, dst_ip, protocol_val))
                        
                    else:
                        if self.debug:
                            print(f"⚠️ Entry {i}: Value too short: {len(value_bytes)} bytes")
                        continue
                        
                except Exception as e:
                    if self.debug:
                        print(f"❌ Error parsing entry {i}: {e}")
                        print(f"   Entry data: {entry}")
                    continue
                    
        except json.JSONDecodeError as e:
            if self.debug:
                print(f"❌ JSON decode error for map {self.map_id}: {e}")
                print(f"   Raw output: {result.stdout[:200]}...")
            return []
        except Exception as e:
            if self.debug:
                print(f"❌ Unexpected error parsing map {self.map_id}: {e}")
                import traceback
                traceback.print_exc()
            return []
            
    
    def update(self, key, value):
        """Update map entry using bpftool"""
        # Implementation for updating whitelist
        pass
    
    def clear(self):
        """Clear all entries from the map with improved error handling"""
        try:
            import subprocess
            import struct
            
            # Get all entries first
            entries_to_delete = list(self.items())
            deleted_count = 0
            total_count = len(entries_to_delete)
            
            if self.debug:
                print(f"🧹 Clearing map {self.map_id} with {total_count} entries...")
            
            if total_count == 0:
                if self.debug:
                    print(f"📋 Map {self.map_id} already empty")
                return True
            
            # Try individual deletion with better error handling
            for key_wrapper, _ in entries_to_delete:
                try:
                    # Determine key format based on map name and key structure
                    if hasattr(key_wrapper, 'src_ip') and hasattr(key_wrapper, 'dst_ip'):
                        # Flow key format: src_ip(4), dst_ip(4), protocol(1), padding(3) = 12 bytes
                        key_bytes = struct.pack('<II', key_wrapper.src_ip, key_wrapper.dst_ip) + bytes([getattr(key_wrapper, 'protocol', 0), 0, 0, 0])
                    elif hasattr(key_wrapper, 'value'):
                        # Old format: just IP address (4 bytes) - pad to 12 bytes if needed for traffic maps
                        if 't_m_' in self.name:
                            # For traffic maps, pad to 12 bytes
                            key_bytes = struct.pack('<I', key_wrapper.value) + bytes([0, 0, 0, 0, 0, 0, 0, 0])
                        else:
                            # For whitelist maps, use 4 bytes
                            key_bytes = struct.pack('<I', key_wrapper.value)
                    else:
                        # Fallback: treat as integer
                        if 't_m_' in self.name:
                            key_bytes = struct.pack('<I', int(key_wrapper)) + bytes([0, 0, 0, 0, 0, 0, 0, 0])
                        else:
                            key_bytes = struct.pack('<I', int(key_wrapper))
                    
                    key_hex_list = [f'0x{b:02x}' for b in key_bytes]
                    cmd = ['bpftool', 'map', 'delete', 'id', str(self.map_id), 'key'] + key_hex_list
                    
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=2.0)
                    if result.returncode == 0:
                        deleted_count += 1
                    elif "No such file or directory" not in result.stderr and "key not found" not in result.stderr:
                        if self.debug:
                            print(f"🗑️ Delete failed for entry: {result.stderr.strip()}")
                            
                except subprocess.TimeoutExpired:
                    if self.debug:
                        print(f"🗑️ Delete timeout for entry")
                    continue
                except Exception as e:
                    if self.debug:
                        print(f"🗑️ Delete error for entry: {e}")
                    continue
            
            # Check remaining entries
            remaining_entries = len(list(self.items()))
            success = remaining_entries == 0
            
            if self.debug:
                print(f"📋 Map {self.map_id}: deleted {deleted_count}/{total_count}, {remaining_entries} remaining")
            
            return success
            
        except Exception as e:
            if self.debug:
                print(f"Error clearing map {self.map_id}: {e}")
            return False


class DoubleBufferRXTXMapWrapper:
    """Enhanced wrapper that manages double buffered RX and TX traffic maps with separate control maps"""
    
    def __init__(self, map_a_rx, map_b_rx, map_a_tx, map_b_tx, 
                 active_buffer_map_rx, active_buffer_map_tx, debug: bool = False):
        self.map_a_rx = map_a_rx
        self.map_b_rx = map_b_rx
        self.map_a_tx = map_a_tx
        self.map_b_tx = map_b_tx
        self.active_buffer_map_rx = active_buffer_map_rx
        self.active_buffer_map_tx = active_buffer_map_tx
        self.debug = debug
        self.name = "double_buffer_rxtx_traffic_map"
        self.map_id = f"double_buffer_rxtx({map_a_rx.map_id},{map_b_rx.map_id},{map_a_tx.map_id},{map_b_tx.map_id})"
        self._current_buffer_rx = 0
        self._current_buffer_tx = 0
    
    def _set_active_buffer_rx(self, buffer_id):
        """Set which RX buffer is active (0=A, 1=B)"""
        try:
            import ctypes
            key = ctypes.c_uint32(0)
            value = ctypes.c_uint32(buffer_id)
            
            self.active_buffer_map_rx[key] = value
            self._current_buffer_rx = buffer_id
            
            if self.debug:
                buffer_name = "A" if buffer_id == 0 else "B"
                print(f"🔄 Set RX active buffer to {buffer_name}")
        except Exception as e:
            if self.debug:
                print(f"Error setting RX active buffer: {e}")
            self._current_buffer_rx = buffer_id

    def _set_active_buffer_tx(self, buffer_id):
        """Set which TX buffer is active (0=A, 1=B)"""
        try:
            import ctypes
            key = ctypes.c_uint32(0)
            value = ctypes.c_uint32(buffer_id)
            
            self.active_buffer_map_tx[key] = value
            self._current_buffer_tx = buffer_id
            
            if self.debug:
                buffer_name = "A" if buffer_id == 0 else "B"
                print(f"🔄 Set TX active buffer to {buffer_name}")
        except Exception as e:
            if self.debug:
                print(f"Error setting TX active buffer: {e}")
            self._current_buffer_tx = buffer_id

    def switch_and_read_inactive(self, flush_after_read: bool = True):
        """Switch buffers independently for RX and TX and return merged data from inactive buffers"""
        try:
            # Determine current buffers
            current_rx = self._current_buffer_rx
            current_tx = self._current_buffer_tx
            
            # Debug: Check buffer contents before switch
            if self.debug:
                print(f"🔍 BEFORE SWITCH - RX buffer: {'A' if current_rx == 0 else 'B'}, TX buffer: {'A' if current_tx == 0 else 'B'}")
                try:
                    a_rx_entries = len(list(self.map_a_rx.items()))
                    b_rx_entries = len(list(self.map_b_rx.items()))
                    a_tx_entries = len(list(self.map_a_tx.items()))
                    b_tx_entries = len(list(self.map_b_tx.items()))
                    print(f"🔍 Buffer A: {a_rx_entries} RX, {a_tx_entries} TX entries")
                    print(f"🔍 Buffer B: {b_rx_entries} RX, {b_tx_entries} TX entries")
                except Exception as e:
                    print(f"🔍 Error checking buffer contents: {e}")
            
            # Switch RX buffer
            new_rx_buffer = 1 if current_rx == 0 else 0
            self._set_active_buffer_rx(new_rx_buffer)
            
            # Switch TX buffer  
            new_tx_buffer = 1 if current_tx == 0 else 0
            self._set_active_buffer_tx(new_tx_buffer)
            
            # Read from previously active (now inactive) buffers
            if current_rx == 0:
                inactive_rx_map = self.map_a_rx
                rx_buffer_name = "A"
            else:
                inactive_rx_map = self.map_b_rx
                rx_buffer_name = "B"
                
            if current_tx == 0:
                inactive_tx_map = self.map_a_tx
                tx_buffer_name = "A"
            else:
                inactive_tx_map = self.map_b_tx
                tx_buffer_name = "B"
            
            if self.debug:
                print(f"🔄 Switched to RX buffer {'B' if new_rx_buffer == 1 else 'A'}, TX buffer {'B' if new_tx_buffer == 1 else 'A'}")
                print(f"🔄 Reading from inactive RX buffer {rx_buffer_name}, TX buffer {tx_buffer_name}")
            
            # Debug: Check inactive buffer contents before reading
            if self.debug:
                try:
                    rx_items = list(inactive_rx_map.items())
                    tx_items = list(inactive_tx_map.items())
                    print(f"🔍 Inactive buffers: {len(rx_items)} RX items, {len(tx_items)} TX items")
                    
                    # Show sample entries
                    if rx_items:
                        for i, (key, stats) in enumerate(rx_items[:3]):
                            print(f"🔍 RX Sample {i}: {getattr(key, 'src_ip', 'unknown')} -> {getattr(key, 'dst_ip', 'unknown')}, bytes: {stats.rx_bytes}")
                    if tx_items:
                        for i, (key, stats) in enumerate(tx_items[:3]):
                            print(f"🔍 TX Sample {i}: {getattr(key, 'src_ip', 'unknown')} -> {getattr(key, 'dst_ip', 'unknown')}, bytes: {stats.tx_bytes}")
                except Exception as e:
                    print(f"🔍 Error checking inactive buffer contents: {e}")
            
            # Merge RX and TX data from inactive buffers
            merged_data = self._merge_rx_tx_data(inactive_rx_map, inactive_tx_map)
            
            # Clear the inactive buffers to prevent duplicates (only if flush_after_read is True)
            #BULK CLEAR the inactive buffers (not individual deletion)
            if flush_after_read and merged_data:
                try:
                    # Method 1: Try bulk clear first
                    rx_clear_success = False
                    tx_clear_success = False
                    
                    if hasattr(inactive_rx_map, 'clear'):
                        rx_clear_success = inactive_rx_map.clear()
                        if self.debug:
                            print(f"🧹 RX buffer {rx_buffer_name} bulk clear: {rx_clear_success}")
                    
                    if hasattr(inactive_tx_map, 'clear'):
                        tx_clear_success = inactive_tx_map.clear()
                        if self.debug:
                            print(f"🧹 TX buffer {tx_buffer_name} bulk clear: {tx_clear_success}")
                    
                    # Only fall back to zero-out if bulk clear completely failed
                    if not (rx_clear_success or tx_clear_success):
                        if self.debug:
                            print(f"🔄 Bulk clear failed, attempting zero-out...")
                        self._zero_out_buffer_counters(inactive_rx_map, rx_buffer_name)
                        self._zero_out_buffer_counters(inactive_tx_map, tx_buffer_name)
                            
                except Exception as e:
                    if self.debug:
                        print(f"Warning: Failed to clear inactive buffers: {e}")
            
            return merged_data
            
        except Exception as e:
            print(f"Error in switch_and_read_inactive: {e}")
            return []

    def _zero_out_buffer_counters(self, buffer_map, buffer_name):
        """Zero out RX/TX counters in a buffer while preserving flow entries"""
        try:
            if self.debug:
                print(f"🔄 Attempting to zero counters in buffer {buffer_name}...")
            
            entries = list(buffer_map.items())
            if not entries:
                return True
            
            zeroed_count = 0
            for key_wrapper, stats in entries:
                try:
                    # Create new stats with zero counters but preserve other fields
                    if hasattr(stats, '__class__'):
                        zero_stats = stats.__class__(
                            0, 0,  # rx_bytes=0, tx_bytes=0
                            getattr(stats, 'dst_ip', 0),
                            getattr(stats, 'protocol', 0)
                        )
                        buffer_map[key_wrapper] = zero_stats
                        zeroed_count += 1
                    else:
                        # Fallback - create simple zero stats
                        class ZeroStats:
                            def __init__(self):
                                self.rx_bytes = 0
                                self.tx_bytes = 0
                                self.dst_ip = getattr(stats, 'dst_ip', 0)
                                self.protocol = getattr(stats, 'protocol', 0)
                        buffer_map[key_wrapper] = ZeroStats()
                        zeroed_count += 1
                        
                except Exception as e:
                    if self.debug:
                        print(f"Could not zero entry in buffer {buffer_name}: {e}")
                    continue
            
            success = zeroed_count == len(entries)
            if self.debug:
                print(f"🔄 Zeroed {zeroed_count}/{len(entries)} entries in buffer {buffer_name}")
            
            return success
            
        except Exception as e:
            if self.debug:
                print(f"Error zeroing buffer {buffer_name}: {e}")
            return False


    def _merge_rx_tx_data(self, rx_map, tx_map):
        """Merge data from RX and TX maps"""
        merged_flows = {}
        
        # Process RX data
        try:
            for key_wrapper, stats in rx_map.items():
                flow_key = (key_wrapper.src_ip, key_wrapper.dst_ip, key_wrapper.protocol)
                if flow_key not in merged_flows:
                    merged_flows[flow_key] = {
                        'rx_bytes': 0,
                        'tx_bytes': 0,
                        'dst_ip': key_wrapper.dst_ip,
                        'protocol': key_wrapper.protocol,
                        'key_wrapper': key_wrapper
                    }
                merged_flows[flow_key]['rx_bytes'] += stats.rx_bytes
        except Exception as e:
            if self.debug:
                print(f"Error reading RX map: {e}")
        
        # Process TX data
        try:
            for key_wrapper, stats in tx_map.items():
                flow_key = (key_wrapper.src_ip, key_wrapper.dst_ip, key_wrapper.protocol)
                if flow_key not in merged_flows:
                    merged_flows[flow_key] = {
                        'rx_bytes': 0,
                        'tx_bytes': 0,
                        'dst_ip': key_wrapper.dst_ip,
                        'protocol': key_wrapper.protocol,
                        'key_wrapper': key_wrapper
                    }
                merged_flows[flow_key]['tx_bytes'] += stats.tx_bytes
        except Exception as e:
            if self.debug:
                print(f"Error reading TX map: {e}")
        
        # Convert to expected format
        result = []
        for flow_key, flow_data in merged_flows.items():
            class TrafficStats:
                def __init__(self, rx, tx, dst, proto):
                    self.rx_bytes = rx
                    self.tx_bytes = tx
                    self.dst_ip = dst
                    self.protocol = proto
            
            result.append((
                flow_data['key_wrapper'],
                TrafficStats(
                    flow_data['rx_bytes'],
                    flow_data['tx_bytes'],
                    flow_data['dst_ip'],
                    flow_data['protocol']
                )
            ))
        
        if self.debug:
            print(f"📊 Merged {len(result)} flows from RX/TX buffers")
        
        return result
    
    def items(self, flush_after_read: bool = True):
        """For compatibility - reads from inactive buffers after switch"""
        return self.switch_and_read_inactive(flush_after_read)
    
    def clear(self):
        """Clear all buffers"""
        try:
            self.map_a_rx.clear()
            self.map_b_rx.clear()
            self.map_a_tx.clear()
            self.map_b_tx.clear()
            return True
        except Exception as e:
            if self.debug:
                print(f"Error clearing double buffer RX/TX: {e}")
            return False


class CombinedWhitelistWrapper:
    """Wrapper to manage both RX and TX whitelist maps"""
    
    def __init__(self, whitelist_map_rx, whitelist_map_tx, debug: bool = False):
        self.whitelist_map_rx = whitelist_map_rx
        self.whitelist_map_tx = whitelist_map_tx
        self.debug = debug
    
    # In the CombinedWhitelistWrapper class, update the __setitem__ method:
    def __setitem__(self, key, value):
        """Set whitelist entry in both RX and TX maps with better error handling"""
        rx_success = False
        tx_success = False
        
        try:
            self.whitelist_map_rx[key] = value
            rx_success = True
            if self.debug:
                print(f"✓ Set whitelist entry in RX map")
        except Exception as e:
            if self.debug:
                print(f"Error setting whitelist entry in RX map: {e}")
        
        try:
            self.whitelist_map_tx[key] = value
            tx_success = True
            if self.debug:
                print(f"✓ Set whitelist entry in TX map")
        except Exception as e:
            if self.debug:
                print(f"Error setting whitelist entry in TX map: {e}")
        
        if not (rx_success or tx_success):
            raise Exception("Failed to set whitelist entry in both RX and TX maps")
        elif not rx_success:
            print(f"Warning: Failed to set whitelist entry in RX map")
        elif not tx_success:
            print(f"Warning: Failed to set whitelist entry in TX map")
        elif self.debug:
            print(f"✓ Set whitelist entry in both RX and TX maps")
    
    # In the CombinedWhitelistWrapper class, update the clear method:
    def clear(self):
        """Clear both whitelist maps with better error handling"""
        rx_cleared = False
        tx_cleared = False
        
        try:
            if hasattr(self.whitelist_map_rx, 'clear'):
                self.whitelist_map_rx.clear()
                rx_cleared = True
                if self.debug:
                    print(f"✓ Cleared RX whitelist map")
        except Exception as e:
            if self.debug:
                print(f"Error clearing RX whitelist map: {e}")
        
        try:
            if hasattr(self.whitelist_map_tx, 'clear'):
                self.whitelist_map_tx.clear()
                tx_cleared = True
                if self.debug:
                    print(f"✓ Cleared TX whitelist map")
        except Exception as e:
            if self.debug:
                print(f"Error clearing TX whitelist map: {e}")
        
        success = rx_cleared and tx_cleared
        if self.debug:
            if success:
                print(f"✓ Successfully cleared both RX and TX whitelist maps")
            else:
                print(f"⚠️ Partial clear: RX={rx_cleared}, TX={tx_cleared}")
        
        return success

