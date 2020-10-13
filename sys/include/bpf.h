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
#include "btree.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef CONFIG_BPF_ENABLE_ALU32
#define CONFIG_BPF_ENABLE_ALU32 (0)
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
    BPF_ILLEGAL_CALL        = -4,
    BPF_ILLEGAL_LEN         = -5,
    BPF_NO_RETURN           = -6,
};

typedef struct bpf_mem_region bpf_mem_region_t;

#define BPF_MEM_REGION_READ     0x01
#define BPF_MEM_REGION_WRITE    0x02
#define BPF_MEM_REGION_EXEC     0x04


struct bpf_mem_region {
    bpf_mem_region_t *next;
    const uint8_t *start;
    size_t len;
    uint8_t flag;
};

#define BPF_FLAG_SETUP_DONE    0x01

typedef struct {
    bpf_mem_region_t stack_region;
    bpf_mem_region_t arg_region;
    const uint8_t *application; /**< Application bytecode */
    size_t application_len;     /**< Application length */
    uint8_t *stack;             /**< VM stack, must be a multiple of 8 bytes and aligned */
    size_t stack_size;          /**< VM stack size in bytes */
    btree_t btree;              /**< Local btree */
    uint16_t flags;
    uint32_t instruction_count;
} bpf_t;

typedef struct bpf_hook bpf_hook_t;

struct bpf_hook {
    struct bpf_hook *next;
    bpf_t *application;
    uint32_t executions;
    bpf_hook_policy_t policy;
};

void bpf_init(void);
void bpf_setup(bpf_t *bpf);

int bpf_execute(bpf_t *bpf, void *ctx, size_t ctx_size, int64_t *result);

int bpf_install_hook(bpf_t *bpf);

void bpf_add_region(bpf_t *bpf, bpf_mem_region_t *region,
                    void *start, size_t len, uint8_t flags);

#ifdef __cplusplus
}
#endif
#endif /* BPF_H */
/** @} */
