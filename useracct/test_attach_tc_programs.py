#!/usr/bin/env python3
"""
Helper script to attach TC programs to interfaces with hyphens
This script handles special cases for hyphenated interfaces
"""

import os
import subprocess
import argparse
import tempfile

def run_command(cmd, verbose=True):
    """Run a command and return result"""
    if verbose:
        print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0 and verbose:
        print(f"Error: {result.stderr}")
    return result

def ensure_clsact_qdisc(interface, verbose=True):
    """Ensure clsact qdisc is setup on interface"""
    # Check if clsact already exists
    check_cmd = ['tc', 'qdisc', 'show', 'dev', interface]
    result = run_command(check_cmd, verbose=False)
    
    if 'clsact' in result.stdout:
        if verbose:
            print(f"✓ Clsact qdisc already exists on {interface}")
        return True
    
    # Add clsact qdisc if it doesn't exist
    cmd = ['tc', 'qdisc', 'add', 'dev', interface, 'clsact']
    result = run_command(cmd, verbose)
    
    if result.returncode == 0:
        if verbose:
            print(f"✓ Added clsact qdisc to {interface}")
        return True
    else:
        if verbose:
            print(f"❌ Failed to add clsact qdisc to {interface}")
        return False

def clean_existing_filters(interface, direction, verbose=True):
    """Clean up existing filters"""
    if verbose:
        print(f"Cleaning existing {direction} filters on {interface}...")
    
    cmd = ['tc', 'filter', 'del', 'dev', interface, direction]
    run_command(cmd, verbose=False)
    return True

def attach_program(interface, direction, object_file=None, prog_fd=None, verbose=True):
    """Attach eBPF program to interface"""
    if verbose:
        print(f"Attaching {direction} program to {interface}...")
    
    # Build the command
    cmd = ['tc', 'filter', 'add', 'dev', interface, direction,
           'prio', '1', 'handle', '1', 'bpf', 'direct-action']
    
    # Add either object file or fd
    if object_file and os.path.exists(object_file):
        # Use different sections for ingress and egress
        if direction == 'ingress':
            cmd.extend(['obj', object_file, 'sec', 'classifier/ingress'])
        else:  # egress
            cmd.extend(['obj', object_file, 'sec', 'classifier/egress'])
    elif prog_fd:
        cmd.extend(['fd', str(prog_fd)])
    else:
        if verbose:
            print("❌ Neither object file nor program fd provided")
        return False
    
    # Run the command
    result = run_command(cmd, verbose)
    
    if result.returncode == 0:
        if verbose:
            print(f"✓ {direction.capitalize()} program attached to {interface}")
        return True
    else:
        if verbose:
            print(f"❌ Failed to attach {direction} program to {interface}")
        return False

def show_filters(interface, direction="both", verbose=True):
    """Show current filters"""
    if verbose:
        print(f"\nCurrent TC filters on {interface}:")
    
    if direction in ["both", "ingress"]:
        cmd = ['tc', 'filter', 'show', 'dev', interface, 'ingress']
        result = run_command(cmd, verbose=False)
        if verbose:
            print("INGRESS FILTERS:")
            print(result.stdout)
    
    if direction in ["both", "egress"]:
        cmd = ['tc', 'filter', 'show', 'dev', interface, 'egress']
        result = run_command(cmd, verbose=False)
        if verbose:
            print("EGRESS FILTERS:")
            print(result.stdout)

def main():
    parser = argparse.ArgumentParser(description='Attach TC BPF programs to interfaces with special handling for hyphenated names')
    parser.add_argument('--interface', '-i', required=True, help='Interface to attach program to')
    parser.add_argument('--object-file', '-o', help='BPF object file path')
    parser.add_argument('--ingress', action='store_true', help='Attach ingress program')
    parser.add_argument('--egress', action='store_true', help='Attach egress program')
    parser.add_argument('--clean', action='store_true', help='Clean existing filters before attaching')
    
    args = parser.parse_args()
    
    # Set default if neither specified
    if not (args.ingress or args.egress):
        args.ingress = True
        args.egress = True
    
    # Ensure qdisc exists
    ensure_clsact_qdisc(args.interface)
    
    # Clean if requested
    if args.clean:
        if args.ingress:
            clean_existing_filters(args.interface, 'ingress')
        if args.egress:
            clean_existing_filters(args.interface, 'egress')
    
    success = True
    
    # Attach programs
    if args.ingress:
        if not attach_program(args.interface, 'ingress', object_file=args.object_file):
            success = False
    
    if args.egress:
        if not attach_program(args.interface, 'egress', object_file=args.object_file):
            success = False
    
    # Show current filters
    show_filters(args.interface)
    
    return 0 if success else 1

if __name__ == '__main__':
    exit(main())
