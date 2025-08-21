#!/usr/bin/env python3

import os
import subprocess
from typing import List, Optional, Dict
try:
    from .utils import run_command
except ImportError:
    from utils import run_command


class NetworkInterface:
    """Network interface management with namespace support"""
    
    def __init__(self, interface: str, namespace: Optional[str] = None):
        self.interface = interface
        self.namespace = namespace
        
    def exists(self) -> bool:
        """Check if interface exists"""
        try:
            cmd = ['cat', f'/sys/class/net/{self.interface}/operstate']
            if self.namespace:
                cmd = ['ip', 'netns', 'exec', self.namespace] + cmd
            
            result = run_command(cmd)
            return result.returncode == 0
        except:
            return False
    
    def is_up(self) -> bool:
        """Check if interface is up"""
        try:
            cmd = ['cat', f'/sys/class/net/{self.interface}/operstate']
            if self.namespace:
                cmd = ['ip', 'netns', 'exec', self.namespace] + cmd
            
            result = run_command(cmd)
            return result.returncode == 0 and result.stdout.strip() == 'up'
        except:
            return False
    
    def get_parent_interface(self) -> str:
        """Get parent interface for VLAN interfaces"""
        try:
            # Check if interface is VLAN (format: eth0.100, ens33.200, etc.)
            if '.' in self.interface:
                parent = self.interface.split('.')[0]
                parent_iface = NetworkInterface(parent, self.namespace)
                if parent_iface.exists():
                    return parent
            
            # Check via ip link show
            cmd = ['ip', 'link', 'show', self.interface]
            if self.namespace:
                cmd = ['ip', 'netns', 'exec', self.namespace] + cmd
            
            result = run_command(cmd)
            if result.returncode == 0 and 'vlan' in result.stdout.lower() and '@' in result.stdout:
                for line in result.stdout.split('\n'):
                    if '@' in line and ':' in line:
                        return line.split('@')[1].split(':')[0]
            
            return self.interface
        except:
            return self.interface
    
    def run_command(self, cmd: List[str]) -> subprocess.CompletedProcess:
        """Execute command in the interface's namespace context"""
        if self.namespace:
            full_cmd = ['ip', 'netns', 'exec', self.namespace] + cmd
        else:
            full_cmd = cmd
        return run_command(full_cmd)


class NetworkTopology:
    """Network topology discovery and management"""
    
    @staticmethod
    def get_namespaces() -> List[str]:
        """Get list of all network namespaces"""
        try:
            result = run_command(['ip', 'netns', 'list'])
            if result.returncode != 0:
                return []
            
            namespaces = []
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    ns_name = line.strip().split()[0]
                    namespaces.append(ns_name)
            return namespaces
        except:
            return []
    
    @staticmethod
    def get_interfaces(namespace: Optional[str] = None) -> List[str]:
        """Get network interfaces in a specific namespace"""
        try:
            cmd = ['ip', 'link', 'show']
            if namespace:
                cmd = ['ip', 'netns', 'exec', namespace] + cmd
            
            result = run_command(cmd)
            if result.returncode != 0:
                return []
            
            interfaces = []
            for line in result.stdout.split('\n'):
                if ': ' in line and not line.startswith(' '):
                    parts = line.split(': ')
                    if len(parts) >= 2:
                        iface_name = parts[1].split('@')[0]
                        if iface_name != 'lo':  # Skip loopback
                            interfaces.append(iface_name)
            
            return interfaces
        except:
            return []
    
    @staticmethod
    def discover_all() -> Dict[str, Dict]:
        """Discover all namespaces and their interfaces"""
        topology = {
            "host": {
                "namespace": None,
                "interfaces": NetworkTopology.get_interfaces(None)
            }
        }
        
        # Add all named namespaces
        namespaces = NetworkTopology.get_namespaces()
        for ns in namespaces:
            topology[ns] = {
                "namespace": ns,
                "interfaces": NetworkTopology.get_interfaces(ns)
            }
        
        return topology
    
    @staticmethod
    def list_all_interfaces():
        """List all interfaces across all namespaces"""
        print("Network Topology Discovery:")
        print("=" * 50)
        
        # Host namespace
        print("\n🏠 Host namespace:")
        interfaces = NetworkTopology.get_interfaces(None)
        if interfaces:
            for iface in interfaces:
                ni = NetworkInterface(iface)
                status = "UP" if ni.is_up() else "DOWN"
                print(f"  📡 {iface} ({status})")
        else:
            print("  No interfaces found")
        
        # Named namespaces
        namespaces = NetworkTopology.get_namespaces()
        for ns in namespaces:
            print(f"\n🏷️  Namespace: {ns}")
            interfaces = NetworkTopology.get_interfaces(ns)
            if interfaces:
                for iface in interfaces:
                    ni = NetworkInterface(iface, ns)
                    status = "UP" if ni.is_up() else "DOWN"
                    print(f"  📡 {iface} ({status})")
            else:
                print("  No interfaces found")
    
    @staticmethod
    def validate_interface(interface: str, namespace: Optional[str] = None) -> bool:
        """Validate interface exists and is up"""
        ni = NetworkInterface(interface, namespace)
        return ni.exists() and ni.is_up()