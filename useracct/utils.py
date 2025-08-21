#!/usr/bin/env python3

import os
import sys
import subprocess
import ipaddress
from typing import List, Optional, Dict


def check_root_privileges():
    """Check if running as root"""
    if os.geteuid() != 0:
        print("❌ This program requires root privileges to attach BPF programs.")
        print(f"Please run: sudo python3 {' '.join(sys.argv)}")
        sys.exit(1)


def format_bytes(bytes_count: int) -> str:
    """Format bytes in human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.2f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.2f} PB"


def ip_to_string(ip_int: int) -> str:
    """Convert integer IP to string format"""
    return str(ipaddress.IPv4Address(ip_int))


def validate_ip_address(ip_str: str) -> bool:
    """Validate IP address format"""
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except ipaddress.AddressValueError:
        return False


def validate_cidr_range(cidr_str: str) -> bool:
    """Validate CIDR range format"""
    try:
        ipaddress.IPv4Network(cidr_str, strict=False)
        return True
    except ipaddress.AddressValueError:
        return False


def expand_cidr_to_ips(cidr_str: str) -> List[str]:
    """Expand CIDR range to list of IP addresses"""
    try:
        network = ipaddress.IPv4Network(cidr_str, strict=False)
        return [str(ip) for ip in network]
    except ipaddress.AddressValueError:
        return []


def run_command(cmd: List[str], capture_output: bool = True, check: bool = False) -> subprocess.CompletedProcess:
    """Execute system command with error handling"""
    try:
        return subprocess.run(cmd, capture_output=capture_output, text=True, check=check)
    except subprocess.CalledProcessError as e:
        if check:
            raise
        return e
    except FileNotFoundError:
        print(f"Command not found: {cmd[0]}")
        return subprocess.CompletedProcess(cmd, 1, "", f"Command not found: {cmd[0]}")


def clean_tc_interface(interface: str):
    """Clean up TC filters and qdiscs on interface"""
    commands = [
        ['tc', 'filter', 'del', 'dev', interface, 'egress'],
        ['tc', 'qdisc', 'del', 'dev', interface, 'clsact']
    ]
    
    for cmd in commands:
        run_command(cmd, capture_output=True, check=False)


def setup_tc_qdisc(interface: str) -> bool:
    """Setup TC clsact qdisc on interface"""
    try:
        # Clean existing qdisc first
        clean_tc_interface(interface)
        
        # Add new clsact qdisc
        result = run_command(['tc', 'qdisc', 'add', 'dev', interface, 'clsact'], check=True)
        return result.returncode == 0
    except subprocess.CalledProcessError:
        return False


def get_parent_interface(interface: str) -> str:
    """Get parent interface for VLAN interfaces"""
    try:
        # Check if interface is VLAN (format: eth0.100, ens33.200, etc.)
        if '.' in interface:
            parent_interface = interface.split('.')[0]
            if os.path.exists(f"/sys/class/net/{parent_interface}"):
                return parent_interface
        
        # Check if it's a VLAN via /proc/net/vlan/
        vlan_proc_path = f"/proc/net/vlan/{interface}"
        if os.path.exists(vlan_proc_path):
            with open(vlan_proc_path, 'r') as f:
                content = f.read()
                for line in content.split('\n'):
                    if 'Device:' in line:
                        return line.split('Device:')[1].strip()
        
        # Check via ip link show
        result = run_command(['ip', 'link', 'show', interface])
        if result.returncode == 0 and 'vlan' in result.stdout.lower() and '@' in result.stdout:
            for line in result.stdout.split('\n'):
                if '@' in line and ':' in line:
                    return line.split('@')[1].split(':')[0]
        
        # Not a VLAN, return same interface
        return interface
        
    except Exception:
        return interface


# Protocol mapping constants
PROTOCOL_NAMES = {
    0: "TCP",
    1: "UDP", 
    2: "ICMP",
    3: "UNKNOWN"
}