# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2018, Oracle and/or its affiliates. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# as published by the Free Software Foundation.
#
# Build bpf code (kernel) out-of-tree by referencing local copies of
# bpf .h files along with headers from kernel source tree.
# Creates similar environment to that used by samples/bpf by adding
# ../include/[bpf_endian.h,bpf_helpers.h,linux/types.h]. The latter is
# used to get definitions for u64, u32 etc which are needed by other kernel
# headers.
#
# - ../include/bpf_helpers.h is a copy of tools/testing/selftest/bpf/bpf_helpers.h
# - ../include/bpf_endian.h is a copy of tools/testing/selftest/bpf/bpf_endian.h
# - ../include/linux/types.h is a copy of tools/include/linux/types.h
#
#
# Assumptions:
#
# - kernel-uek-devel package or equivalent has installed (partial) source
#   tree in /usr/src/kernels/`uname -r`
#
# - llc/clang are available and support "bpf" target; check with "llc --verison"
#

OBJS = btree.o sample_saul.o sample_storage.o fletcher32.o sample_test.o sample.o

LLC ?= llc
CLANG ?= clang
INC_FLAGS = -nostdinc -isystem `$(CLANG) -print-file-name=include`
EXTRA_CFLAGS ?= -Os -emit-llvm

RIOTBASE = ../../..

BPFINCLUDE = -I$(RIOTBASE)/sys/include/ -I$(RIOTBASE)/drivers/include/ -I$(RIOTBASE)/core/include

LLC_FLAGS ?=

LLC_FLAGS += -march=bpf
ifeq (BPF_ENABLE_ALU32,1)
  LLC_FLAGS += -mattr=+alu32
endif

all: $(OBJS)

.PHONY: clean

clean:
	rm -f $(OBJS)

INC_FLAGS = -nostdinc -isystem `$(CLANG) -print-file-name=include`

$(OBJS):  %.o:%.c
	$(CLANG) $(INC_FLAGS) \
	        -Wno-unused-value -Wno-pointer-sign -g3 \
	        -Wno-compare-distinct-pointer-types \
	        -Wno-gnu-variable-sized-type-not-at-end \
	        -Wno-address-of-packed-member -Wno-tautological-compare \
	        -Wno-unknown-warning-option \
	        $(BPFINCLUDE) $(LINUXINCLUDE) \
	        $(EXTRA_CFLAGS) -c $< -o -| $(LLC) $(LLC_FLAGS) -filetype=obj -o $@
