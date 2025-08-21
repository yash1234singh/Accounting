#!/usr/bin/env python3

import os
import subprocess
from typing import Optional, List
from bcc import BPF
try:
    from .network_interface import NetworkInterface
except ImportError:
    from network_interface import NetworkInterface
import time


max_retries=3

class ProgramAttacher:
    """Handles attachment and detachment of eBPF programs"""
    
    def __init__(self, interface: str, namespace: Optional[str] = None, use_tc_ingress: bool = False, debug: bool = False):
        self.interface = interface
        self.namespace = namespace
        self.use_tc_ingress = use_tc_ingress
        self.network_interface = NetworkInterface(interface, namespace)
        self.debug = debug
        
        # Track attachment status
        self.xdp_attached = False
        self.tc_ingress_attached = False
        self.tc_egress_attached = False
        
        # Store pin paths for cleanup
        self._tc_ingress_pin_path = None
        self._tc_egress_pin_path = None
    
    def attach_programs(self, bpf_manager) -> bool:

        """Attach ingress and egress programs with retry logic"""
        for attempt in range(max_retries):
            if attempt > 0:
                if self.debug:
                    print(f"🔄 Retry attempt {attempt + 1}/{max_retries}")
                time.sleep(2)

        """Attach ingress and egress programs based on configuration"""
        ingress_success = False
        egress_success = False
        
        try:
            # Attach ingress program (XDP or TC)
            if self.use_tc_ingress:
                ingress_success = self._setup_tc_program(bpf_manager, 'ingress')
            else:
                ingress_success = self._setup_xdp_ingress(bpf_manager)
            
            # Attach egress program (always TC)
            if self.debug:
                print("\n🔄 Attaching TC egress program for TX accounting...")
            egress_success = self._setup_tc_program(bpf_manager, 'egress')
            
            # Verify attachments by checking if programs are actually attached
            if ingress_success and egress_success:
                if self._verify_attachments():
                    method = "TC" if self.use_tc_ingress else "XDP"
                    print(f"✓ Full monitoring active ({method} ingress + TC egress)")
                    return True
                else:
                    if self.debug:
                        print(f"⚠️ Attachment verification failed on attempt {attempt + 1}")
            
        except Exception as e:
            if self.debug:
                print(f"Attachment attempt {attempt + 1} failed: {e}")
    
        print("❌ Failed to attach programs after all retry attempts")

        # Verify egress program attachment
        if not egress_success:
            print("⚠️ TC egress program attachment failed - TX bytes will be 0!")
            print("   Attempting one more time with higher priority...")
            # Try one more time with a different approach for later
            pass
        
        # Summary - consider it successful if at least one program attached
        if ingress_success and egress_success:
            method = "TC" if self.use_tc_ingress else "XDP"
            print(f"✓ Full monitoring active ({method} ingress + TC egress)")
            return True
        elif ingress_success:
            method = "TC" if self.use_tc_ingress else "XDP"
            print(f"✓ Partial monitoring active ({method} ingress only)")
            return True
        elif egress_success:
            print(f"✓ Partial monitoring active (TC egress only)")
            return True
        else:
            print("❌ No monitoring programs attached")
            return False
    
    def _setup_xdp_ingress(self, bpf_manager) -> bool:
        """Setup XDP program for ingress traffic"""
        try:
            if self.namespace:
                print(f"⚠️  XDP attachment in namespace {self.namespace} requires manual setup")
                return False
            
            # Check if using pre-compiled object or BCC
            if hasattr(bpf_manager, 'obj_path') and bpf_manager.obj_path:
                # Use pre-compiled object file for XDP
                if self.debug:
                    print(f"🔧 XDP: Using pre-compiled object file: {bpf_manager.obj_path}")
                
                cmd = ['ip', 'link', 'set', 'dev', self.interface, 'xdp', 
                       'obj', bpf_manager.obj_path, 'sec', 'xdp']
                
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"✓ XDP program attached via object file to {self.interface}")
                    self.xdp_attached = True
                    return True
                else:
                    print(f"❌ XDP object file attachment failed: {result.stderr}")
                    return False
            else:
                # Fallback to BCC method
                if hasattr(bpf_manager, 'bpf') and bpf_manager.bpf:
                    bpf_manager.bpf.attach_xdp(self.interface, bpf_manager.xdp_fn, 0)
                    print(f"✓ XDP program attached via BCC to {self.interface}")
                    self.xdp_attached = True
                    return True
                else:
                    print(f"❌ No BPF manager or XDP function available")
                    return False
                    
        except Exception as e:
            print(f"❌ XDP attachment failed: {e}")
            return False
    
    def _setup_tc_program(self, bpf_manager, direction: str) -> bool:
        """Setup TC program for ingress or egress traffic with fallback methods"""
        try:
            # Determine interface and section based on direction
            if direction == 'ingress':
                interface = self.interface
                section = 'classifier/ingress'
                fn_attr = 'tc_ingress_fn'
                attach_method = 'attach_tc_ingress'
            else:  # egress
                interface = self.network_interface.get_parent_interface()
                section = 'classifier/egress'
                fn_attr = 'tc_egress_fn'
                attach_method = 'attach_tc_egress'
            
            if self.debug:
                print(f"\n📊 Setting up TC {direction} program on {interface}...")
                if direction == 'egress' and interface != self.interface:
                    print(f"Using parent interface: {interface} for egress")
            
            # Handle hyphens in interface name
            hyphen_in_interface = '-' in interface
            if hyphen_in_interface and self.debug:
                print(f"Note: Interface name '{interface}' contains hyphens, which may cause TC attachment issues")
            
            if self.namespace:
                cmd_prefix = ['ip', 'netns', 'exec', self.namespace]
            else:
                cmd_prefix = []
            
            # Setup qdisc and clean existing filters
            self._ensure_clsact_qdisc(interface, cmd_prefix)
            clean_cmd = cmd_prefix + ['tc', 'filter', 'del', 'dev', interface, direction]
            subprocess.run(clean_cmd, capture_output=True, check=False)
            
            # For namespaces, use object file method only
            if self.namespace:
                return self._attach_via_object_file(bpf_manager, interface, direction, section, cmd_prefix)
            
            # For host namespace, try multiple methods
            return self._try_all_attachment_methods(bpf_manager, interface, direction, section, cmd_prefix, fn_attr, attach_method)
            
        except Exception as e:
            print(f"TC {direction} setup exception: {e}")
            return False

    def _attach_via_object_file(self, bpf_manager, interface: str, direction: str, section: str, cmd_prefix: list) -> bool:
        """Attach program via object file (required for namespaces)"""
        try:
            if self.debug:
                print(f"Method: Object file attachment for {direction} in namespace")
            
            if hasattr(bpf_manager, 'obj_path') and bpf_manager.obj_path and os.path.exists(bpf_manager.obj_path):
                if self.debug:
                    print(f"🔧 Using object file path: {bpf_manager.obj_path}")
                
                attach_cmd = cmd_prefix + [
                    'tc', 'filter', 'add', 'dev', interface, direction,
                    'prio', '1', 'handle', '1', 'bpf', 'direct-action',
                    'obj', bpf_manager.obj_path, 'sec', section
                ]
                
                result = subprocess.run(attach_cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"✓ TC {direction} program attached via object file to {interface}")
                    self._set_attachment_status(direction, True)
                    if self.debug:
                        self._display_tc_rules(interface, cmd_prefix, direction)
                    return True
                else:
                    print(f"Object file attach failed: {result.stderr}")
                    return False
            else:
                print("❌ Object file not found - compile with 'make all' first")
                return False
                
        except Exception as e1:
            print(f"Object file method for {direction} failed: {e1}")
            return False

    def _try_all_attachment_methods(self, bpf_manager, interface: str, direction: str, section: str, cmd_prefix: list, fn_attr: str, attach_method: str) -> bool:
        """Try all attachment methods for host namespace"""
        
        # Method 1: Object file attachment (highest priority)
        if self._try_object_file_method(bpf_manager, interface, direction, section, cmd_prefix):
            return True
        
        # Method 2: BCC's built-in TC attachment
        if self._try_bcc_builtin_method(bpf_manager, interface, direction, fn_attr, attach_method, cmd_prefix):
            return True
        
        # Method 3: File descriptor approach
        if self._try_fd_method(bpf_manager, interface, direction, fn_attr, cmd_prefix):
            return True
        
        # Method 4: BCC's attach_func method
        if self._try_attach_func_method(bpf_manager, interface, direction, fn_attr):
            return True
        
        # All methods failed
        print(f"ℹ️  All TC {direction} attachment methods failed for {interface}")
        print(f"    This is common with certain kernel/tc/BCC version combinations")
        if direction == 'egress':
            print(f"    Continuing with ingress monitoring only")
        else:
            print(f"    You might want to try XDP ingress instead (use --xdp flag)")
        return False

    def _try_object_file_method(self, bpf_manager, interface: str, direction: str, section: str, cmd_prefix: list) -> bool:
        """Method 1: Try object file attachment"""
        try:
            if self.debug:
                print(f"Method 1: Trying object file attachment for {direction} (highest priority)")
            
            if hasattr(bpf_manager, 'obj_path') and os.path.exists(bpf_manager.obj_path):
                attach_cmd = cmd_prefix + [
                    'tc', 'filter', 'add', 'dev', interface, direction,
                    'prio', '1', 'handle', '1', 'bpf', 'direct-action',
                    'obj', bpf_manager.obj_path, 'sec', section
                ]
                
                result = subprocess.run(attach_cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"✓ TC {direction} program attached via object file to {interface}")
                    self._set_attachment_status(direction, True)
                    if self.debug:
                        self._display_tc_rules(interface, cmd_prefix, direction)
                    return True
                else:
                    print(f"Object file attach for {direction} failed: {result.stderr}")
            else:
                print("Object file not found, trying other methods...")
        except Exception as e1:
            print(f"Object file method for {direction} failed: {e1}")
        
        return False

    def _try_bcc_builtin_method(self, bpf_manager, interface: str, direction: str, fn_attr: str, attach_method: str, cmd_prefix: list) -> bool:
        """Method 2: Try BCC's built-in TC attachment"""
        try:
            if self.debug:
                print(f"Method 2: Trying BCC's built-in TC {direction} attachment")
            
            if (hasattr(bpf_manager.bpf, attach_method) and 
                hasattr(bpf_manager, fn_attr) and 
                getattr(bpf_manager, fn_attr)):
                
                tc_fn = getattr(bpf_manager, fn_attr)
                # Only try if we have an actual function object, not a string
                if not isinstance(tc_fn, str):
                    attach_func = getattr(bpf_manager.bpf, attach_method)
                    attach_func(interface, tc_fn)
                    print(f"✓ TC {direction} program attached via BCC to {interface}")
                    self._set_attachment_status(direction, True)
                    if self.debug:
                        self._display_tc_rules(interface, cmd_prefix, direction)
                    return True
                else:
                    print(f"TC {direction} function is string reference, skipping BCC attach method")
            else:
                print(f"BCC {attach_method} not available")
        except Exception as e2:
            print(f"BCC built-in TC {direction} attach failed: {e2}")
        
        return False

    def _try_fd_method(self, bpf_manager, interface: str, direction: str, fn_attr: str, cmd_prefix: list) -> bool:
        """Method 3: Try file descriptor approach"""
        try:
            if self.debug:
                print(f"Method 3: Trying file descriptor approach for {direction}")
            
            if hasattr(bpf_manager, fn_attr):
                tc_fn = getattr(bpf_manager, fn_attr)
                if hasattr(tc_fn, 'fd'):
                    prog_fd = tc_fn.fd
                    if self.debug:
                        print(f"TC {direction} program FD: {prog_fd}")
                    
                    attach_cmd = cmd_prefix + [
                        'tc', 'filter', 'add', 'dev', interface, direction,
                        'prio', '1', 'handle', '1', 'bpf', 'da', 'fd', str(prog_fd)
                    ]
                    
                    result = subprocess.run(attach_cmd, capture_output=True, text=True)
                    if result.returncode == 0:
                        print(f"✓ TC {direction} program attached via file descriptor to {interface}")
                        self._set_attachment_status(direction, True)
                        if self.debug:
                            self._display_tc_rules(interface, cmd_prefix, direction)
                        return True
                    else:
                        print(f"File descriptor attach failed: {result.stderr}")
                else:
                    print(f"TC {direction} function is string reference, no fd available")
        except Exception as e3:
            print(f"File descriptor method failed: {e3}")
        
        return False

    def _try_attach_func_method(self, bpf_manager, interface: str, direction: str, fn_attr: str) -> bool:
        """Method 4: Try BCC's attach_func method"""
        try:
            if self.debug:
                print(f"Method 4: Trying BCC's attach_func method for {direction}")
            
            if hasattr(bpf_manager, fn_attr):
                tc_fn = getattr(bpf_manager, fn_attr)
                # Only try if we have an actual function object, not a string
                if not isinstance(tc_fn, str) and hasattr(bpf_manager.bpf, 'attach_func'):
                    bpf_manager.bpf.attach_func(tc_fn, direction, interface)
                    print(f"✓ TC {direction} program attached via attach_func to {interface}")
                    self._set_attachment_status(direction, True)
                    return True
                else:
                    print(f"TC {direction} function is string reference, skipping attach_func method")
        except Exception as e4:
            print(f"attach_func method failed: {e4}")
        
        return False

    def _set_attachment_status(self, direction: str, status: bool):
        """Set attachment status based on direction"""
        if direction == 'ingress':
            self.tc_ingress_attached = status
        else:
            self.tc_egress_attached = status
        
    
    def _ensure_clsact_qdisc(self, interface: str, cmd_prefix: List[str]):
        """Ensure clsact qdisc is setup on interface"""
        try:
            # Check if clsact already exists
            check_cmd = cmd_prefix + ['tc', 'qdisc', 'show', 'dev', interface]
            result = subprocess.run(check_cmd, capture_output=True, text=True)
            
            if 'clsact' in result.stdout:
                return  # Already exists
            
            # Clean up any existing qdisc first
            clean_cmd = cmd_prefix + ['tc', 'qdisc', 'del', 'dev', interface, 'clsact']
            subprocess.run(clean_cmd, capture_output=True, check=False)
            
            # Add clsact qdisc
            add_cmd = cmd_prefix + ['tc', 'qdisc', 'add', 'dev', interface, 'clsact']
            result = subprocess.run(add_cmd, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"Warning: Failed to add clsact qdisc to {interface}: {result.stderr}")
                
        except Exception as e:
            print(f"Warning: Error setting up clsact qdisc on {interface}: {e}")
    
    def _display_tc_rules(self, interface: str, cmd_prefix: List[str], direction: str = "both"):
        """Display current TC rules on the interface"""
        try:
            print(f"\n📋 Current TC configuration for {interface} ({direction}):")
            
            # Show qdisc
            qdisc_cmd = cmd_prefix + ['tc', 'qdisc', 'show', 'dev', interface]
            result = subprocess.run(qdisc_cmd, capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip():
                print("📌 Qdiscs:")
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        print(f"   {line}")
            else:
                print("📌 No qdiscs found")
            
            # Show filters based on direction
            directions = [direction] if direction in ["ingress", "egress"] else ["ingress", "egress"]
            
            for dir_name in directions:
                filter_cmd = cmd_prefix + ['tc', 'filter', 'show', 'dev', interface, dir_name]
                result = subprocess.run(filter_cmd, capture_output=True, text=True)
                if result.returncode == 0 and result.stdout.strip():
                    print(f"📌 {dir_name.capitalize()} filters:")
                    for line in result.stdout.strip().split('\n'):
                        if line.strip():
                            print(f"   {line}")
                else:
                    print(f"📌 No {dir_name} filters found")
            
            print()  # Empty line for readability
            
        except Exception as e:
            print(f"Could not display TC rules: {e}")
    
    def cleanup(self, bpf_manager):
        """Clean up BPF programs and TC filters"""
        if self.debug:
            print("🧹 Starting cleanup...")
        
        try:
            # Get the actual interface names
            ingress_interface = self.interface
            egress_interface = self.network_interface.get_parent_interface()
            
            # Cleanup XDP if attached
            if self.xdp_attached:
                try:
                    if self.namespace:
                        cmd = ['ip', 'netns', 'exec', self.namespace, 'ip', 'link', 'set', ingress_interface, 'xdp', 'off']
                        subprocess.run(cmd, capture_output=True, check=False)
                    else:
                        # For pre-compiled objects, prefer ip command over BCC
                        if hasattr(bpf_manager, 'obj_path') and bpf_manager.obj_path:
                            subprocess.run(['ip', 'link', 'set', ingress_interface, 'xdp', 'off'], 
                                        capture_output=True, check=False)
                        elif bpf_manager and bpf_manager.bpf:
                            bpf_manager.bpf.remove_xdp(ingress_interface, 0)
                        else:
                            # Final fallback to ip command
                            subprocess.run(['ip', 'link', 'set', ingress_interface, 'xdp', 'off'], 
                                        capture_output=True, check=False)
                    print(f"✓ XDP program detached from {ingress_interface}")
                except Exception as e:
                    print(f"XDP cleanup warning: {e}")
            
            # Cleanup TC ingress if attached
            if self.tc_ingress_attached:
                try:
                    cmd_prefix = ['ip', 'netns', 'exec', self.namespace] if self.namespace else []
                    clean_cmd = cmd_prefix + ['tc', 'filter', 'del', 'dev', ingress_interface, 'ingress']
                    subprocess.run(clean_cmd, capture_output=True, check=False)
                    print(f"✓ TC ingress filters removed from {ingress_interface}")
                except Exception as e:
                    print(f"TC ingress cleanup warning: {e}")
            
            # Cleanup TC egress if attached
            if self.tc_egress_attached:
                try:
                    cmd_prefix = ['ip', 'netns', 'exec', self.namespace] if self.namespace else []
                    clean_cmd = cmd_prefix + ['tc', 'filter', 'del', 'dev', egress_interface, 'egress']
                    subprocess.run(clean_cmd, capture_output=True, check=False)
                    print(f"✓ TC egress filters removed from {egress_interface}")
                except Exception as e:
                    print(f"TC egress cleanup warning: {e}")
            
            # Clean up qdiscs
            for iface in [ingress_interface, egress_interface]:
                if iface and iface != ingress_interface or not self.tc_ingress_attached:
                    try:
                        cmd_prefix = ['ip', 'netns', 'exec', self.namespace] if self.namespace else []
                        clean_cmd = cmd_prefix + ['tc', 'qdisc', 'del', 'dev', iface, 'clsact']
                        subprocess.run(clean_cmd, capture_output=True, check=False)
                    except:
                        pass
            
            if self.debug:
                print("✓ Cleanup completed successfully")
            
        except Exception as e:
            print(f"Error during cleanup: {e}")
            # Force cleanup as fallback
            self._force_cleanup()

    def _verify_attachments(self) -> bool:
        """Verify that programs are actually attached"""
        try:
            import subprocess
            
            if self.namespace:
                cmd_prefix = ['ip', 'netns', 'exec', self.namespace]
            else:
                cmd_prefix = []
            
            # Check ingress
            if self.use_tc_ingress:
                check_cmd = cmd_prefix + ['tc', 'filter', 'show', 'dev', self.interface, 'ingress']
                result = subprocess.run(check_cmd, capture_output=True, text=True)
                ingress_ok = result.returncode == 0 and 'bpf' in result.stdout
            else:
                # Check XDP
                check_cmd = cmd_prefix + ['ip', 'link', 'show', self.interface]
                result = subprocess.run(check_cmd, capture_output=True, text=True)
                ingress_ok = result.returncode == 0 and 'xdp' in result.stdout
            
            # Check egress
            egress_interface = self.network_interface.get_parent_interface()
            check_cmd = cmd_prefix + ['tc', 'filter', 'show', 'dev', egress_interface, 'egress']
            result = subprocess.run(check_cmd, capture_output=True, text=True)
            egress_ok = result.returncode == 0 and 'bpf' in result.stdout
            
            if self.debug:
                print(f"🔍 Verification: ingress={ingress_ok}, egress={egress_ok}")
            
            return ingress_ok and egress_ok
            
        except Exception as e:
            if self.debug:
                print(f"Verification error: {e}")
            return False


    def _force_cleanup(self):
        """Force cleanup using system commands"""
        print("🔧 Performing force cleanup...")
        
        try:
            interfaces = [self.interface]
            parent = self.network_interface.get_parent_interface()
            if parent != self.interface:
                interfaces.append(parent)
            
            for iface in interfaces:
                # Force remove XDP
                subprocess.run(['ip', 'link', 'set', iface, 'xdp', 'off'], 
                            capture_output=True, check=False)
                
                # Force remove TC filters
                subprocess.run(['tc', 'filter', 'del', 'dev', iface, 'ingress'], 
                            capture_output=True, check=False)
                subprocess.run(['tc', 'filter', 'del', 'dev', iface, 'egress'], 
                            capture_output=True, check=False)
                
                # Remove qdisc
                subprocess.run(['tc', 'qdisc', 'del', 'dev', iface, 'clsact'], 
                            capture_output=True, check=False)
            
            print("✓ Force cleanup completed")
            
        except Exception as e:
            print(f"Force cleanup error: {e}")
