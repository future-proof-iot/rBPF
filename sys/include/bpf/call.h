/*
 * Copyright (C) 2020 Inria
 * Copyright (C) 2020 Koen Zandberg <koen@bergzand.net>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef BPF_CALL_H
#define BPF_CALL_H

#include <stdint.h>
#include "bpf/shared.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t (*bpf_call_t)(uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);

uint32_t bpf_vm_printf(uint32_t fmt, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4);


#ifdef __cplusplus
}
#endif
#endif /* BPF_CALL_H */

