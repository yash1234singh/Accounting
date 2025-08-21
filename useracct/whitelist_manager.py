#!/usr/bin/env python3

import os
import json
import ctypes
from ctypes import Structure, c_uint8
from typing import Set, Dict, List, Optional
from datetime import datetime
import ipaddress
try:
    from .utils import validate_ip_address, validate_cidr_range, expand_cidr_to_ips
except ImportError:
    from utils import validate_ip_address, validate_cidr_range, expand_cidr_to_ips


class WhitelistEntry(Structure):
    """C structure mapping for whitelist_entry"""
    _fields_ = [("exists", c_uint8)]


class WhitelistManager:
    """Manages IP whitelist with JSON and text format support"""
    
    def __init__(self, whitelist_file: str, output_dir: str = ".", debug: bool = False):
        self.whitelist_file = whitelist_file
        self.output_dir = output_dir
        self.whitelisted_ips: Set[str] = set()
        self.whitelist_path = os.path.join(output_dir, whitelist_file)
        self.last_mtime = 0
        self.debug = debug
        
    def load_whitelist(self) -> bool:
        """Load whitelist from JSON or text file"""
        # Handle legacy whitelist file names
        legacy_names = ["white_list.txt", "white_list.json"]
        
        if not os.path.exists(self.whitelist_path):
            # Try legacy names in the same directory
            for legacy_name in legacy_names:
                legacy_path = os.path.join(self.output_dir, legacy_name)
                if os.path.exists(legacy_path):
                    print(f"ℹ Found legacy whitelist file: {legacy_name}")
                    self.whitelist_path = legacy_path
                    self.whitelist_file = legacy_name
                    break
            else:
                print(f"ℹ No whitelist file found at {self.whitelist_path}")
                return False
        
        try:
            # Determine file format by extension
            if self.whitelist_path.endswith('.json'):
                return self._load_json_whitelist()
            else:
                print(f"ℹ Unsupported whitelist file format: {self.whitelist_path}")
                return False
        except Exception as e:
            print(f"Error loading whitelist: {e}")
            return False
    
    def _load_json_whitelist(self) -> bool:
        """Load whitelist from JSON file"""
        try:
            with open(self.whitelist_path, 'r') as f:
                whitelist_data = json.load(f)
            
            self.whitelisted_ips.clear()
            
            if "whitelist" in whitelist_data:
                for category_name, category_data in whitelist_data["whitelist"].items():
                    if not isinstance(category_data, dict) or not category_data.get("enabled", False):
                        continue
                    
                    # Process individual IPs
                    for ip in category_data.get("ips", []):
                        if validate_ip_address(ip):
                            self.whitelisted_ips.add(ip)
                        else:
                            print(f"Warning: Invalid IP in {category_name}: {ip}")
                    
                    # Process CIDR ranges
                    for cidr in category_data.get("cidrs", []):
                        if validate_cidr_range(cidr):
                            ips = expand_cidr_to_ips(cidr)
                            self.whitelisted_ips.update(ips)
                        else:
                            print(f"Warning: Invalid CIDR in {category_name}: {cidr}")
            
            if self.debug:
                print(f"✓ Loaded {len(self.whitelisted_ips)} IPs from JSON whitelist")
            return True
            
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in whitelist file: {e}")
            return False
    
    
    def is_whitelisted(self, ip_str: str) -> bool:
        """Check if IP is whitelisted"""
        return ip_str in self.whitelisted_ips
    
    # In the populate_bpf_map method, ensure it handles the combined wrapper correctly:
    def populate_bpf_map(self, whitelist_map) -> bool:
        """Populate eBPF whitelist map (handles both single and combined maps)"""
        if not whitelist_map:
            print("Warning: Whitelist map not available - continuing without whitelist filtering")
            return True
        
        try:
            # Clear existing entries
            if hasattr(whitelist_map, 'clear'):
                whitelist_map.clear()
            
            # Add each whitelisted IP to the map
            entry = WhitelistEntry(exists=1)

            for ip_str in self.whitelisted_ips:
                try:
                    ip_int = int(ipaddress.IPv4Address(ip_str))
                    key = ctypes.c_uint32(ip_int)
                    
                    # Handle both single maps and combined wrapper
                    whitelist_map[key] = entry
                    
                    if self.debug:
                        print(f"✓ Added {ip_str} to whitelist map(s)")
                        
                except Exception as e:
                    print(f"Error adding IP {ip_str} to BPF map: {e}")
            
            if self.debug:
                map_type = "combined RX/TX" if hasattr(whitelist_map, 'whitelist_map_rx') else "single"
                print(f"✓ Populated {map_type} whitelist map with {len(self.whitelisted_ips)} IPs")
            return True
            
        except Exception as e:
            print(f"Error populating whitelist map: {e}")
            print("Continuing without whitelist filtering")
            return True
    
    def reload_if_changed(self, whitelist_map=None) -> bool:
        """Reload whitelist if file has been modified"""
        if not os.path.exists(self.whitelist_path):
            return False
        
        try:
            current_mtime = os.path.getmtime(self.whitelist_path)
            if current_mtime > self.last_mtime:
                if self.debug:
                    print("📝 Whitelist file modified, reloading...")
                old_count = len(self.whitelisted_ips)
                
                if self.load_whitelist():
                    self.last_mtime = current_mtime
                    if whitelist_map:
                        try:
                            self.populate_bpf_map(whitelist_map)
                        except Exception as e:
                            print(f"Warning: Could not update BPF whitelist map: {e}")  
                    
                    new_count = len(self.whitelisted_ips)
                    
                    if self.debug:
                        print(f"✓ Whitelist reloaded: {old_count} -> {new_count} IPs")
                    return True
            
            return False
        except Exception as e:
            print(f"Error checking whitelist file: {e}")
            return False
    
    def get_sample_ips(self, count: int = 10) -> List[str]:
        """Get sample whitelisted IPs for display"""
        return sorted(list(self.whitelisted_ips)[:count])
    
    def get_count(self) -> int:
        """Get count of whitelisted IPs"""
        return len(self.whitelisted_ips)
    
    def create_example_json(self, filepath: str = None) -> bool:
        """Create example JSON whitelist file"""
        if filepath is None:
            filepath = self.whitelist_path
        
        example_data = {
            "metadata": {
                "description": "Network Accounting Whitelist",
                "version": "1.0",
                "created": datetime.now().isoformat(),
                "auto_reload": True
            },
            "whitelist": {
                "localhost": {
                    "description": "Localhost",
                    "enabled": True,
                    "ips": ["127.0.0.1"],
                    "cidrs": []
                },
                "private_networks": {
                    "description": "Private networks (RFC 1918)",
                    "enabled": False,
                    "ips": [],
                    "cidrs": ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]
                },
                "dns_servers": {
                    "description": "Public DNS servers",
                    "enabled": False,
                    "ips": ["8.8.8.8", "8.8.4.4", "1.1.1.1"],
                    "cidrs": []
                }
            }
        }
        
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            with open(filepath, 'w') as f:
                json.dump(example_data, f, indent=2)
            return True
        except Exception as e:
            print(f"Error creating example JSON: {e}")
            return False
    
    