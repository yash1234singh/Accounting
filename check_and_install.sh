#!/bin/bash

# Enhanced script to check and install BPF packages with kernel headers fix
# Includes automatic kernel headers resolution

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

# ============================================================================
# KERNEL HEADERS FIX FUNCTIONS (embedded from fix_kernel_headers.sh)
# ============================================================================

KERNEL_VER=$(uname -r)

# Function to check if kernel headers exist
check_kernel_headers() {
    local paths=(
        "/lib/modules/$KERNEL_VER/build"
        "/usr/src/kernels/$KERNEL_VER"
        "/usr/src/linux-headers-$KERNEL_VER"
    )
    
    for path in "${paths[@]}"; do
        if [ -d "$path" ]; then
            return 0
        fi
    done
    return 1
}

# Function to install exact kernel headers
install_exact_headers() {
    # Try different package name variations
    local packages=(
        "kernel-devel-$KERNEL_VER"
        "kernel-headers-$KERNEL_VER" 
        "kernel-devel-$(echo $KERNEL_VER | sed 's/\.el9_4\.x86_64$//')"
    )
    
    for pkg in "${packages[@]}"; do
        if dnf install -y "$pkg" 2>/dev/null; then
            return 0
        fi
    done
    return 1
}

# Function to install generic kernel headers
install_generic_headers() {
    local packages=(
        "kernel-devel"
        "kernel-headers"
        "kernel-tools"
        "kernel-tools-libs"
    )
    
    dnf install -y "${packages[@]}" --nobest --skip-broken --nogpgcheck 2>/dev/null || return 1
    return 0
}

# Function to create symlink if headers exist but in wrong location
create_symlink() {
    # Find any kernel headers that might be installed
    local found_headers=""
    for dir in /usr/src/kernels/*; do
        if [ -d "$dir" ]; then
            found_headers="$dir"
            break
        fi
    done
    
    if [ -n "$found_headers" ]; then
        local target="/lib/modules/$KERNEL_VER/build"
        if [ ! -e "$target" ]; then
            mkdir -p "/lib/modules/$KERNEL_VER"
            ln -sf "$found_headers" "$target" 2>/dev/null
            return 0
        fi
    fi
    return 1
}

# Function to download and install headers manually
manual_install() {
    dnf install -y kernel-devel kernel-headers --nobest --skip-broken --nogpgcheck 2>/dev/null || return 1
    return 0
}

# Function to verify BTF support
check_btf_support() {
    if [ -f "/sys/kernel/btf/vmlinux" ]; then
        return 0
    else
        return 1
    fi
}

# Main kernel headers fix function
fix_kernel_headers_automatically() {
    log_info "Kernel headers not found. Attempting automatic fix..."
    
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

# ============================================================================
# MAIN PACKAGE INSTALLATION LOGIC
# ============================================================================

log_info "Checking required packages for BPF program..."

# Required packages
REQUIRED_PACKAGES=(
    "clang"
    "llvm" 
    "kernel-devel"
    "kernel-headers"
    "libbpf-devel"
    "bcc"
    "python3-bcc"
    "bpftool"
)

# Check what's missing
MISSING_PACKAGES=()
for pkg in "${REQUIRED_PACKAGES[@]}"; do
    if rpm -q "$pkg" &>/dev/null; then
        log_success "$pkg is already installed"
    else
        log_info "$pkg is missing"
        MISSING_PACKAGES+=("$pkg")
    fi
done

# Check Python3 (special case)
if command -v python3 &>/dev/null; then
    log_success "python3 is available"
else
    log_info "python3 is missing"
    MISSING_PACKAGES+=("python3")
fi

# Install only missing packages
if [ ${#MISSING_PACKAGES[@]} -eq 0 ]; then
    log_success "All required packages are already installed!"
else
    log_info "Installing missing packages: ${MISSING_PACKAGES[*]}"
    
    # Clean DNF cache and disable problematic repos
    log_info "Cleaning DNF cache and fixing repository issues..."
    dnf clean all
    
    # Disable any problematic repositories
    for repo in $(dnf repolist all 2>/dev/null | grep -i "baseos\|appstream" | grep -v "enabled" | awk '{print $1}' || true); do
        dnf config-manager --disable "$repo" 2>/dev/null || true
    done
    
    # Enable EPEL if not already enabled (for BCC packages)
    if ! dnf repolist enabled | grep -q epel; then
        log_info "Enabling EPEL repository..."
        dnf install -y epel-release 2>/dev/null || {
            log_error "Failed to install EPEL, trying to continue without it..."
        }
    fi
    
    # Install only missing packages without upgrades, suppress GPG errors
    log_info "Installing packages with --nobest --skip-broken to avoid upgrades..."
    dnf install -y --nobest --skip-broken --nogpgcheck "${MISSING_PACKAGES[@]}" 2>/dev/null || {
        log_error "Some packages failed to install, but continuing with verification..."
    }
fi

echo
log_info "Verifying installation..."

# Verify critical components
ERRORS=0

# Check clang
if command -v clang &>/dev/null; then
    log_success "clang: $(clang --version | head -n1 | awk '{print $3}')"
else
    log_error "clang not found"
    ((ERRORS++))
fi

# Check kernel headers with automatic fix
if check_kernel_headers; then
    log_success "Kernel headers: available for $KERNEL_VER"
    
    # Also verify BTF support
    if check_btf_support; then
        log_success "BTF support: available (eBPF CO-RE ready)"
    else
        log_info "BTF support: not available (will use legacy BPF)"
    fi
else
    log_error "Kernel headers not found for $KERNEL_VER"
    
    # Attempt automatic fix
    if fix_kernel_headers_automatically; then
        log_success "Kernel headers: automatically fixed!"
        
        # Recheck BTF support
        if check_btf_support; then
            log_success "BTF support: available (eBPF CO-RE ready)"
        else
            log_info "BTF support: not available (will use legacy BPF)"
        fi
    else
        log_error "Automatic kernel headers fix failed"
        echo
        echo "Manual steps to fix kernel headers:"
        echo "1. Check available packages: dnf list available | grep kernel-devel"
        echo "2. Install closest version: sudo dnf install kernel-devel kernel-headers"
        echo "3. Create symlink if needed:"
        echo "   sudo mkdir -p /lib/modules/$KERNEL_VER"
        echo "   sudo ln -sf /usr/src/kernels/[version] /lib/modules/$KERNEL_VER/build"
        echo
        ((ERRORS++))
    fi
fi

# Check BCC
if python3 -c "from bcc import BPF" 2>/dev/null; then
    log_success "BCC: Python integration working"
else
    log_error "BCC: Python integration failed"
    
    # Try to fix BCC installation
    log_info "Attempting to fix BCC installation..."
    if dnf install -y python3-bcc bcc-tools --nobest --skip-broken 2>/dev/null; then
        if python3 -c "from bcc import BPF" 2>/dev/null; then
            log_success "BCC: Fixed successfully"
        else
            log_error "BCC: Still not working after fix attempt"
            ((ERRORS++))
        fi
    else
        ((ERRORS++))
    fi
fi

# Check bpftool
if command -v bpftool &>/dev/null; then
    log_success "bpftool: available"
else
    log_info "bpftool not found, trying to install..."
    if dnf install -y bpftool --nobest --skip-broken 2>/dev/null; then
        log_success "bpftool: installed successfully"
    else
        log_error "bpftool: installation failed"
        ((ERRORS++))
    fi
fi

echo
if [ $ERRORS -eq 0 ]; then
    log_success "All components verified! Ready to run BPF programs."
    echo
    echo "You can now run:"
    echo "  sudo python3 network_accounting.py <interface>"
    echo "  Example: sudo python3 network_accounting.py eth0"
    echo
    
    # Show system info
    echo "System Information:"
    echo "  Kernel: $KERNEL_VER"
    echo "  Clang: $(clang --version | head -n1 | awk '{print $3}' 2>/dev/null || echo 'Unknown')"
    echo "  BTF Support: $(check_btf_support && echo 'Yes' || echo 'No')"
    echo "  BCC Version: $(python3 -c "import bcc; print(bcc.__version__)" 2>/dev/null || echo 'Unknown')"
    
else
    log_error "$ERRORS errors found. Some components may not work properly."
    echo
    echo "Common troubleshooting steps:"
    echo "1. Reboot the system to ensure kernel modules are properly loaded"
    echo "2. Check SELinux status: getenforce (set to Permissive if needed)"
    echo "3. Verify network interface name: ip link show"
    echo "4. Test with a simple eBPF program first"
fi

echo
echo "For additional troubleshooting, check the logs:"
echo "  dmesg | grep -i bpf"
echo "  journalctl -xe | grep -i bpf"