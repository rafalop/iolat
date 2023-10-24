#!/bin/bash

set -x
if [[ -f /sys/fs/bpf/io_latency ]]; then rm -f /sys/fs/bpf/io_latency; fi

set -e

# generate vmlinux.h
if [[ ! -f ./vmlinux.h ]]; then bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; fi 

 
#clang -O2 -g -Wall -Werror -target bpf -D __TARGET_ARCH_x86 -c io_latency.c -o io_latency.o -I./

# Generate bpf code and build iolat
go generate
go build -o iolat iolat.go bpf_bpfel_x86.go
