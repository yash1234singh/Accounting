# Variables
CC = clang
CFLAGS = -target bpf -Wall -O2 -g -I ebpf
SOURCE = ebpf/network_accounting.bpf.c
CONFIG = config/multi_accounting_config.json
DEFAULT_OBJ = build/objects/network_accounting.bpf.o
BUILD_DIR = build/objects

# Default target
all: compile-tagged

# Compile single default object file
compile: $(SOURCE)
	@echo "🔧 Compiling single BPF object file..."
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $(SOURCE) -o $(DEFAULT_OBJ)
	@echo "✓ Single object file compiled: $(DEFAULT_OBJ)"

# Compile tagged object files based on config
compile-tagged: $(SOURCE) $(CONFIG)
	@echo "🔧 Generating tagged BPF object files from config..."
	@if [ ! -f $(CONFIG) ]; then \
		echo "ℹ️ No $(CONFIG) found, creating default object only"; \
		$(MAKE) compile; \
		exit 0; \
	fi
	@echo "📋 Processing instances from $(CONFIG)..."
	@# Ensure required directories exist
	@mkdir -p $(BUILD_DIR) logs config
	@jq -r '.instances[]? | select(.tag != null and .tag != "") | .tag' $(CONFIG) 2>/dev/null | while read -r tag; do \
		if [ -n "$$tag" ]; then \
			echo "🔧 Processing tag: $$tag"; \
			tagged_c="$(BUILD_DIR)/network_accounting_$$tag.bpf.c"; \
			tagged_o="$(BUILD_DIR)/network_accounting_$$tag.bpf.o"; \
			echo "🔍 Debug: Creating tagged C file: $$tagged_c"; \
			sed -e "s/} t_m_a_r SEC/} t_m_a_r_$$tag SEC/g" \
			    -e "s/} t_m_b_r SEC/} t_m_b_r_$$tag SEC/g" \
			    -e "s/} t_m_a_t SEC/} t_m_a_t_$$tag SEC/g" \
			    -e "s/} t_m_b_t SEC/} t_m_b_t_$$tag SEC/g" \
			    -e "s/} a_buf_r SEC/} a_buf_r_$$tag SEC/g" \
			    -e "s/} a_buf_t SEC/} a_buf_t_$$tag SEC/g" \
			    -e "s/} w_m_r SEC/} w_m_r_$$tag SEC/g" \
			    -e "s/} w_m_t SEC/} w_m_t_$$tag SEC/g" \
			    -e "s/&t_m_a_r/\&t_m_a_r_$$tag/g" \
			    -e "s/&t_m_b_r/\&t_m_b_r_$$tag/g" \
			    -e "s/&t_m_a_t/\&t_m_a_t_$$tag/g" \
			    -e "s/&t_m_b_t/\&t_m_b_t_$$tag/g" \
			    -e "s/&a_buf_r/\&a_buf_r_$$tag/g" \
			    -e "s/&a_buf_t/\&a_buf_t_$$tag/g" \
			    -e "s/&w_m_r/\&w_m_r_$$tag/g" \
			    -e "s/&w_m_t/\&w_m_t_$$tag/g" \
			    $(SOURCE) > "$$tagged_c"; \
			echo "🔍 Debug: Attempting compilation with: $(CC) $(CFLAGS) -c $$tagged_c -o $$tagged_o"; \
			if $(CC) $(CFLAGS) -c "$$tagged_c" -o "$$tagged_o" 2>logs/compile_error.log; then \
				echo "✓ Created $$tagged_o"; \
				rm -f "$$tagged_c"; \
			else \
				echo "✗ Failed to compile $$tagged_o"; \
				echo "🔍 Debug: Compilation error:"; \
				cat logs/compile_error.log; \
				echo "🔍 Debug: Generated C file content (first 20 lines):"; \
				head -20 "$$tagged_c"; \
				echo "🔍 Debug: Map structure patterns:"; \
				grep -n "} .*_SEC" "$$tagged_c" | head -10; \
				rm -f "$$tagged_c" logs/compile_error.log; \
			fi; \
		fi; \
	done
	@echo "📦 Tagged object file generation completed"

# Clean up generated files
clean:
	@echo "🧹 Cleaning up generated files..."
	rm -f $(BUILD_DIR)/*.bpf.o
	rm -f $(BUILD_DIR)/network_accounting_*.bpf.c
	rm -f logs/compile*.log
	@echo "✓ Cleanup completed"

# Clean up eBPF resources
cleanup:
	@echo "🧹 Cleaning up eBPF resources..."
	sudo python3 useracct/cleanup_bpf.py --verbose || echo "⚠️ cleanup_bpf.py failed or not found"

# Force cleanup
force-cleanup:
	@echo "🧹 Force cleaning up eBPF resources..."
	sudo python3 useracct/cleanup_bpf.py --force --verbose || echo "⚠️ cleanup_bpf.py failed or not found"

# Run single instance (requires compile first)
run: compile
	@echo "🚀 Running single instance on eth0..."
	sudo python3 -m useracct.network_accounting eth0

# Run multi-instance (requires compile-tagged first)
multi-run: compile-tagged
	@echo "🚀 Running multi-instance manager..."
	sudo python3 -m useracct.multi_network_accounting $(CONFIG)

# Debug single instance
debug: compile
	@echo "🐛 Running single instance in debug mode..."
	sudo python3 -m useracct.network_accounting --debug eth0

# Debug multi-instance
multi-debug: compile-tagged
	@echo "🐛 Running multi-instance manager in debug mode..."
	sudo python3 -m useracct.multi_network_accounting --debug $(CONFIG)

# Verify that tagged object files have correct map names
verify-tags:
	@echo "🔍 Verifying tagged object files..."
	@for obj in $(BUILD_DIR)/network_accounting_*.bpf.o; do \
		if [ -f "$$obj" ]; then \
			tag=$$(echo "$$obj" | sed 's/network_accounting_\(.*\)\.bpf\.o/\1/'); \
			echo "📁 Checking $$obj (tag: $$tag):"; \
			if command -v llvm-objdump >/dev/null 2>&1; then \
				echo "  Map symbols:"; \
				llvm-objdump -t "$$obj" | grep -E "(t_m_|a_buf|w_m)" | head -10 || echo "  No map symbols found"; \
			else \
				echo "  llvm-objdump not available, skipping symbol check"; \
			fi; \
		fi; \
	done

# Check system dependencies
check:
	@echo "🔍 Checking system dependencies..."
	@which clang > /dev/null || (echo "❌ clang not found" && exit 1)
	@which jq > /dev/null || (echo "❌ jq not found - install with: sudo dnf install jq" && exit 1)
	@which bpftool > /dev/null || (echo "❌ bpftool not found" && exit 1)
	@which tc > /dev/null || (echo "❌ tc not found" && exit 1)
	@echo "✓ All dependencies found"

# Install system dependencies
install-deps:
	@echo "📦 Installing system dependencies..."
	sudo ./check_and_install.sh

# Create example config file
example-config:
	@echo "📝 Creating example configuration..."
	sudo python3 -m useracct.multi_network_accounting --create-example

# Verify compiled object files
verify: 
	@echo "🔍 Verifying compiled object files..."
	@for obj in $(BUILD_DIR)/*.bpf.o; do \
		if [ -f "$$obj" ]; then \
			echo "📁 $$obj:"; \
			llvm-objdump -h "$$obj" | grep -E "\.maps|\.text" || echo "  No standard sections found"; \
		fi; \
	done

# List all available BPF maps (requires root)
list-maps:
	@echo "🗺️ Listing current BPF maps..."
	@sudo bpftool map list | grep -E "(traffic|whitelist|a_buf)" || echo "No network accounting maps found"

# List all BPF programs (requires root)
list-progs:
	@echo "📋 Listing current BPF programs..."
	@sudo bpftool prog list | grep -E "(traffic|classifier)" || echo "No network accounting programs found"

# Show help
help:
	@echo "🚀 Network Accounting eBPF Build System"
	@echo ""
	@echo "Main targets:"
	@echo "  all              - Build tagged object files (default)"
	@echo "  compile          - Build single default object file" 
	@echo "  compile-tagged   - Build tagged object files from config"
	@echo "  clean           - Remove generated files"
	@echo ""
	@echo "Running:"
	@echo "  run             - Run single instance"
	@echo "  multi-run       - Run multi-instance manager"
	@echo "  debug           - Run single instance with debug"
	@echo "  multi-debug     - Run multi-instance with debug"
	@echo ""
	@echo "Maintenance:"
	@echo "  cleanup         - Clean up eBPF resources"
	@echo "  force-cleanup   - Force clean eBPF resources"
	@echo "  check           - Check system dependencies"
	@echo "  install-deps    - Install system dependencies"
	@echo ""
	@echo "Utilities:"
	@echo "  verify          - Verify compiled object files"
	@echo "  verify-tags     - Verify compiled object files with "
	@echo "  list-maps       - List current BPF maps"
	@echo "  list-progs      - List current BPF programs"
	@echo "  example-config  - Create example config file"

# Declare phony targets
.PHONY: all compile compile-tagged clean cleanup force-cleanup run multi-run debug multi-debug check install-deps example-config verify list-maps list-progs help

# Default to help if no target specified
.DEFAULT_GOAL := all