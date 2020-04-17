/*
 * Copyright (C) 2020 Inria
 * Copyright (C) 2020 Koen Zandberg <koen@bergzand.net>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    sys_bpf (Extended) Berkeley Packet Filter compliant virtual machine
 * @ingroup     sys
 * @brief       API for eBPF-based scripts
 *
 *
 * @{
 *
 * @file
 * @brief       [eBPF](https://www.kernel.org/doc/html/latest/bpf/index.html)
 *
 * @author      Koen Zandberg <koen@bergzand.net>
 */

#ifndef BPF_H
#define BPF_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    BPF_POLICY_CONTINUE,            /**< Always execute next hook */
    BPF_POLICY_ABORT_ON_NEGATIVE,   /**< Execute next script unless result is negative */
    BPF_POLICY_ABORT_ON_POSITIVE,   /**< Execute next script unless result is non-zero positive */
    BPF_POLICY_SINGLE,              /**< Always stop after this execution */
} bpf_hook_policy_t;

typedef enum {
    BPF_HOOK_TRIGGER_NETIF,

    BPF_HOOK_NUM,
} bpf_hook_trigger_t;

enum {
    BPF_OK = 0,
    BPF_ILLEGAL_INSTRUCTION = -1,
    BPF_ILLEGAL_MEM         = -2,
    BPF_ILLEGAL_JUMP        = -3,
};

typedef struct {
    const uint8_t *application;
    size_t application_len;
    uint8_t *stack;     /**< VM stack, must be a multiple of 8 bytes and aligned */
    size_t stack_size;  /**< VM stack size in bytes */
} bpf_t;

typedef struct bpf_hook bpf_hook_t;

struct bpf_hook {
    struct bpf_hook *next;
    bpf_t *application;
    uint32_t executions;
    bpf_hook_policy_t policy;
};

int bpf_execute(bpf_t *bpf, void *ctx, int64_t *result);

int bpf_install_hook(bpf_t *bpf);

#ifdef __cplusplus
}
#endif
#endif /* BPF_H */
/** @} */
