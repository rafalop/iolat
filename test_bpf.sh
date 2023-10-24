#!/bin/bash

## Test loading io_latency.c file

#set -x
if [[ -f /sys/fs/bpf/io_latency ]]; then rm -f /sys/fs/bpf/io_latency; fi

set -e

# generate vmlinux.h
if [[ ! -f ./vmlinux.h ]]; then bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; fi 

# build object file and try to load it
# -I should point to your vmlinux.h, should generate automatically from above (requires bpftool installed)
clang -O2 -g -Wall -Werror -target bpf -D __TARGET_ARCH_x86 -c io_latency.c -o io_latency.o -I./
bpftool prog load io_latency.o /sys/fs/bpf/io_latency

# clean up
rm /sys/fs/bpf/io_latency

echo "Successfully built and loaded bpf object file."

