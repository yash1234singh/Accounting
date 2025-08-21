#!/bin/bash

# Script to fix kernel headers issue on AlmaLinux 9
# Handles multiple scenarios for missing kernel headers
# Can be called standalone or from check_and_install.sh

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${YELLOW}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_debug() { echo -e "${BLUE}[DEBUG]${NC} $1"; }

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
    echo "Please run: sudo $0"
    exit 1
fi

KERNEL_VER=$(uname -r)
log_info "Current kernel version: $KERNEL_VER"

# Function to check if kernel headers exist
check_kernel_headers() {
    local paths=(
        "/lib/modules/$KERNEL_VER/build"
        "/usr/src/kernels/$KERNEL_VER"
        "/usr/src/linux-headers-$KERNEL_VER"
    )
    
    for path in "${paths[@]}"; do
        if [ -d "$path" ]; then
            log_success "Found kernel headers at: $path"
            return 0
        fi
    done
    return 1
}

# Function to install exact kernel headers
install_exact_headers() {
    log_info "Attempting to install exact kernel headers for $KERNEL_VER..."
    
    # Try different package name variations
    local packages=(
        "kernel-devel-$KERNEL_VER"
        "kernel-headers-$KERNEL_VER" 
        "kernel-devel-$(echo $KERNEL_VER | sed 's/\.el9_4\.x86_64$//')"
    )
    
    for pkg in "${packages[@]}"; do
        log_info "Trying to install: $pkg"
        if dnf install -y "$pkg" 2>/dev/null; then
            log_success "Successfully installed: $pkg"
            return 0
        else
            log_error "Failed to install: $pkg"
        fi
    done
    return 1
}

# Function to install generic kernel headers
install_generic_headers() {
    log_info "Installing generic kernel development packages..."
    
    local packages=(
        "kernel-devel"
        "kernel-headers"
        "kernel-tools"
        "kernel-tools-libs"
    )
    
    dnf install -y "${packages[@]}" || {
        log_error "Failed to install generic kernel packages"
        return 1
    }
    
    log_success "Generic kernel packages installed"
    return 0
}

# Function to create symlink if headers exist but in wrong location
create_symlink() {
    log_info "Searching for existing kernel headers..."
    
    # Find any kernel headers that might be installed
    local found_headers=""
    for dir in /usr/src/kernels/*; do
        if [ -d "$dir" ]; then
            found_headers="$dir"
            log_info "Found headers at: $dir"
            break
        fi
    done
    
    if [ -n "$found_headers" ]; then
        local target="/lib/modules/$KERNEL_VER/build"
        if [ ! -e "$target" ]; then
            log_info "Creating symlink: $target -> $found_headers"
            mkdir -p "/lib/modules/$KERNEL_VER"
            ln -sf "$found_headers" "$target"
            log_success "Symlink created successfully"
            return 0
        fi
    fi
    return 1
}

# Function to download and install headers manually
manual_install() {
    log_info "Attempting manual installation..."
    
    # Get the base kernel version without architecture
    local base_version=$(echo "$KERNEL_VER" | sed 's/\.el9_4\.x86_64$//')
    log_debug "Base version: $base_version"
    
    # Try to find the package in repositories
    log_info "Searching for available kernel-devel packages..."
    dnf search kernel-devel 2>/dev/null | grep -i "kernel-devel" || {
        log_error "No kernel-devel packages found in repositories"
        return 1
    }
    
    # Install the closest available version
    dnf install -y kernel-devel kernel-headers --nobest --skip-broken || {
        log_error "Failed to install any kernel headers"
        return 1
    }
    
    log_success "Installed available kernel headers"
    return 0
}

# Function to verify BTF support
check_btf_support() {
    log_info "Checking BTF (BPF Type Format) support..."
    
    if [ -f "/sys/kernel/btf/vmlinux" ]; then
        log_success "BTF support available - eBPF CO-RE will work"
        return 0
    else
        log_error "BTF support not available"
        log_info "You may need to use older BPF compilation methods"
        return 1
    fi
}

# Function to be called from check_and_install.sh
fix_kernel_headers_from_parent() {
    log_info "Attempting to fix kernel headers..."
    
    # Clean DNF cache first
    dnf clean all >/dev/null 2>&1
    
    # Strategy 1: Try to install exact version
    if install_exact_headers; then
        if check_kernel_headers; then
            log_success "Successfully installed exact kernel headers!"
            check_btf_support >/dev/null 2>&1
            return 0
        fi
    fi
    
    # Strategy 2: Install generic headers and create symlink
    if install_generic_headers; then
        if check_kernel_headers; then
            log_success "Generic headers work!"
            check_btf_support >/dev/null 2>&1
            return 0
        elif create_symlink; then
            if check_kernel_headers; then
                log_success "Headers fixed with symlink!"
                check_btf_support >/dev/null 2>&1
                return 0
            fi
        fi
    fi
    
    # Strategy 3: Manual installation with best available
    if manual_install; then
        if create_symlink; then
            if check_kernel_headers; then
                log_success "Manual installation succeeded!"
                check_btf_support >/dev/null 2>&1
                return 0
            fi
        fi
    fi
    
    return 1
}

# Main execution
main() {
    echo "=================================="
    echo "Kernel Headers Fix Script"
    echo "=================================="
    
    # First check if headers already exist
    if check_kernel_headers; then
        log_success "Kernel headers are already properly installed!"
        check_btf_support
        exit 0
    fi
    
    log_info "Kernel headers not found. Attempting to fix..."
    
    # Clean DNF cache first
    log_info "Cleaning DNF cache..."
    dnf clean all
    
    # Strategy 1: Try to install exact version
    if install_exact_headers; then
        if check_kernel_headers; then
            log_success "Successfully installed exact kernel headers!"
            check_btf_support
            exit 0
        fi
    fi
    
    # Strategy 2: Install generic headers and create symlink
    log_info "Exact headers failed. Trying generic installation..."
    if install_generic_headers; then
        if check_kernel_headers; then
            log_success "Generic headers work!"
            check_btf_support
            exit 0
        elif create_symlink; then
            if check_kernel_headers; then
                log_success "Headers fixed with symlink!"
                check_btf_support
                exit 0
            fi
        fi
    fi
    
    # Strategy 3: Manual installation with best available
    log_info "Trying manual installation with best available packages..."
    if manual_install; then
        if create_symlink; then
            if check_kernel_headers; then
                log_success "Manual installation succeeded!"
                check_btf_support
                exit 0
            fi
        fi
    fi
    
    # If all else fails, provide manual instructions
    echo
    log_error "Automatic fix failed. Manual steps required:"
    echo
    echo "1. Check available kernel packages:"
    echo "   dnf list available | grep kernel-devel"
    echo
    echo "2. Install the closest version:"
    echo "   sudo dnf install kernel-devel kernel-headers"
    echo
    echo "3. Create manual symlink if needed:"
    echo "   sudo mkdir -p /lib/modules/$KERNEL_VER"
    echo "   sudo ln -sf /usr/src/kernels/[available-version] /lib/modules/$KERNEL_VER/build"
    echo
    echo "4. For eBPF development without exact headers:"
    echo "   - Use BTF-based CO-RE if available"
    echo "   - Consider updating to a supported kernel"
    echo "   - Use userspace alternatives like libpcap"
    
    exit 1
}

# Run the main function
main