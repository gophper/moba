# Makefile for tcp_tracker eBPF program

CLANG ?= clang
LLVM_STRIP ?= $(shell which llvm-strip-16 || which llvm-strip)
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Try to find vmlinux.h in common locations
VMLINUX_H := $(shell if [ -f /sys/kernel/btf/vmlinux ]; then echo "vmlinux.h exists or will be generated"; else echo ""; fi)

# BPF program
BPF_OBJ := tcp_tracker.bpf.o

# Compiler flags
INCLUDES := -I. -I/usr/include -I/usr/include/$(shell uname -m)-linux-gnu
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES)

.PHONY: all clean vmlinux

all: $(BPF_OBJ)

# Generate vmlinux.h if it doesn't exist
vmlinux.h:
	@if [ -f /sys/kernel/btf/vmlinux ]; then \
		echo "Generating vmlinux.h from BTF..."; \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; \
	else \
		echo "Error: /sys/kernel/btf/vmlinux not found. Please ensure BTF is enabled in your kernel."; \
		echo "Creating minimal vmlinux.h stub..."; \
		echo '#ifndef __VMLINUX_H__' > vmlinux.h; \
		echo '#define __VMLINUX_H__' >> vmlinux.h; \
		echo '#include <linux/types.h>' >> vmlinux.h; \
		echo 'struct task_struct;' >> vmlinux.h; \
		echo 'struct sock;' >> vmlinux.h; \
		echo 'struct socket;' >> vmlinux.h; \
		echo 'struct net;' >> vmlinux.h; \
		echo 'struct ns_common { unsigned int inum; };' >> vmlinux.h; \
		echo '#endif' >> vmlinux.h; \
	fi

# Build BPF object
$(BPF_OBJ): tcp_tracker.c tcp_tracker.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c tcp_tracker.c -o $(BPF_OBJ)
	$(LLVM_STRIP) -g $(BPF_OBJ)

clean:
	rm -f $(BPF_OBJ) vmlinux.h

# Test target to verify compilation
test: $(BPF_OBJ)
	@echo "BPF program compiled successfully!"
	@file $(BPF_OBJ)
