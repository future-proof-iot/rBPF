/*
 * Copyright (C) 2020 Inria
 * Copyright (C) 2020 Koen Zandberg <koen@bergzand.net>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include "bpf.h"
#include "bpf/instruction.h"
#include "bpf/call.h"

#define ENABLE_DEBUG (0)
#include "debug.h"

static int _check_mem(const bpf_t *bpf, uint8_t size, const intptr_t addr, uint8_t type)
{
    const intptr_t end = addr + size;
    for (const bpf_mem_region_t *region = &bpf->stack_region; region; region = region->next) {
        if ((addr  >= (intptr_t)region->start) &&
                (end <= (intptr_t)(region->start + region->len)) &&
                (region->flag & type)) {

            return 0;
        }
    }

    DEBUG("Denied access to %p with len %u\n",(void*)addr, end - addr);
    return -1;
}

static inline int _check_load(const bpf_t *bpf, uint8_t size, const intptr_t addr)
{
    return _check_mem(bpf, size, addr, BPF_MEM_REGION_READ);
}

static inline int _check_store(const bpf_t *bpf, uint8_t size, const intptr_t addr)
{
    return _check_mem(bpf, size, addr, BPF_MEM_REGION_WRITE);
}

static int _preflight_checks(const bpf_t *bpf)
{
    if (bpf->application_len % sizeof(bpf_instruction_t)) {
        return BPF_ILLEGAL_LEN;
    }

    size_t num_instructions = bpf->application_len/sizeof(bpf_instruction_t);
    const bpf_instruction_t *instr = (const bpf_instruction_t*)bpf->application;

    if (instr[num_instructions - 1].opcode != 0x95) {
        return BPF_NO_RETURN;
    }
    return BPF_OK;
}

static bpf_call_t _bpf_get_call(uint32_t num)
{
    switch(num) {
        case BPF_FUNC_BPF_PRINTF:
            return &bpf_vm_printf;
        case BPF_FUNC_BPF_STORE_LOCAL:
            return &bpf_vm_store_local;
        case BPF_FUNC_BPF_STORE_GLOBAL:
            return &bpf_vm_store_global;
        case BPF_FUNC_BPF_FETCH_LOCAL:
            return &bpf_vm_fetch_local;
        case BPF_FUNC_BPF_FETCH_GLOBAL:
            return &bpf_vm_fetch_global;
        case BPF_FUNC_BPF_NOW_MS:
            return &bpf_vm_now_ms;
        case BPF_FUNC_BPF_SAUL_REG_FIND_NTH:
            return &bpf_vm_saul_reg_find_nth;
        case BPF_FUNC_BPF_SAUL_REG_FIND_TYPE:
            return &bpf_vm_saul_reg_find_type;
        case BPF_FUNC_BPF_SAUL_REG_READ:
            return &bpf_vm_saul_reg_read;
#ifdef MODULE_GCOAP
        case BPF_FUNC_BPF_GCOAP_RESP_INIT:
            return &bpf_vm_gcoap_resp_init;
        case BPF_FUNC_BPF_COAP_OPT_FINISH:
            return &bpf_vm_coap_opt_finish;
#endif
        default:
            return NULL;
    }
}

#define DST regmap[instr->dst]
#define SRC regmap[instr->src]
#define IMM instr->immediate

#define CONT       { goto select_instr; }
#define CONT_JUMP  { goto jump_instr; }


#if (CONFIG_BPF_ENABLE_ALU32)
#define ALU(OPCODE, OP)         \
    ALU64_##OPCODE##_REG:         \
        DST = DST OP SRC;       \
        CONT;                   \
    ALU64_##OPCODE##_IMM:       \
        DST = DST OP IMM;       \
        CONT;                   \
    ALU32_##OPCODE##_REG:         \
        DST = (uint32_t) DST OP (uint32_t) SRC;   \
        CONT;                   \
    ALU32_##OPCODE##_IMM:           \
        DST = (uint32_t) DST OP (uint32_t) IMM;   \
        CONT;
#else
#define ALU(OPCODE, OP)         \
    ALU64_##OPCODE##_REG:         \
        DST = DST OP SRC;       \
        CONT;                   \
    ALU64_##OPCODE##_IMM:       \
        DST = DST OP IMM;       \
        CONT;
#endif

#define COND_JMP(SIGN, OPCODE, CMP_OP)              \
    JMP_##OPCODE##_REG:                  \
        jump_cond = (SIGN##nt64_t) DST CMP_OP (SIGN##nt64_t)SRC; \
        CONT_JUMP;                           \
    JMP_##OPCODE##_IMM:                 \
        jump_cond = (SIGN##nt64_t) DST CMP_OP (SIGN##nt64_t)IMM; \
        CONT_JUMP;                           \

#if CONFIG_BPF_ENABLE_ALU32
#define ALU_OPCODE_REG(OPCODE, VALUE) \
    [VALUE | 0x0C ] = &&ALU32_##OPCODE##_REG, \
    [VALUE | 0x0F ] = &&ALU64_##OPCODE##_REG

#define ALU_OPCODE_IMM(OPCODE, VALUE)   \
    [VALUE | 0x04 ] = &&ALU32_##OPCODE##_IMM, \
    [VALUE | 0x07 ] = &&ALU64_##OPCODE##_IMM
#else
#define ALU_OPCODE_REG(OPCODE, VALUE) \
    [VALUE | 0x0F ] = &&ALU64_##OPCODE##_REG

#define ALU_OPCODE_IMM(OPCODE, VALUE)   \
    [VALUE | 0x07 ] = &&ALU64_##OPCODE##_IMM
#endif

#define ALU_OPCODE(OPCODE, VALUE) \
    ALU_OPCODE_REG(OPCODE, VALUE), \
    ALU_OPCODE_IMM(OPCODE, VALUE)

#define JMP_OPCODE(OPCODE, VALUE) \
    [VALUE | 0x05] = &&JMP_##OPCODE##_IMM, \
    [VALUE | 0x0D] = &&JMP_##OPCODE##_REG

#define MEM_OPCODE(OPCODE, VALUE) \
    [VALUE | 0x10] = &&MEM_##OPCODE##_BYTE, \
    [VALUE | 0x08] = &&MEM_##OPCODE##_HALF, \
    [VALUE | 0x00] = &&MEM_##OPCODE##_WORD, \
    [VALUE | 0x18] = &&MEM_##OPCODE##_LONG \

int bpf_run(bpf_t *bpf, const void *ctx, int64_t *result)
{
    int res = BPF_OK;
    bpf->instruction_count = 0;
    uint64_t regmap[11] = { 0 };
    regmap[1] = (uint64_t)(uintptr_t)ctx;
    regmap[10] = (uint64_t)(uintptr_t)(bpf->stack + bpf->stack_size);

    const bpf_instruction_t *instr = (const bpf_instruction_t*)bpf->application;
    bool jump_cond = false;

    res = _preflight_checks(bpf);
    if (res < 0) {
        return res;
    }

    static const void * const _jumptable[256] = {
        ALU_OPCODE(ADD, 0x00),
        ALU_OPCODE(SUB, 0x10),
        ALU_OPCODE(MUL, 0x20),
        ALU_OPCODE(DIV, 0x30),
        ALU_OPCODE(OR,  0x40),
        ALU_OPCODE(AND, 0x50),
        ALU_OPCODE(LSH, 0x60),
        ALU_OPCODE(RSH, 0x70),
        ALU_OPCODE(MOD, 0x90),
        ALU_OPCODE(XOR, 0xa0),
        ALU_OPCODE(MOV, 0xb0),
        ALU_OPCODE(ARSH, 0xc0),
        ALU_OPCODE_REG(NEG, 0x80),

        [0x05] = &&JUMP_ALWAYS,
        JMP_OPCODE(EQ, 0x10),
        JMP_OPCODE(GT, 0x20),
        JMP_OPCODE(GE, 0x30),
        JMP_OPCODE(LT, 0xA0),
        JMP_OPCODE(LE, 0xB0),
        JMP_OPCODE(SET, 0x40),
        JMP_OPCODE(NE, 0x50),
        JMP_OPCODE(SGT, 0x60),
        JMP_OPCODE(SGE, 0x70),
        JMP_OPCODE(SLT, 0xC0),
        JMP_OPCODE(SLE, 0xD0),

        [0x18] = &&MEM_LDDW_IMM,

        MEM_OPCODE(STX, 0x63),
        MEM_OPCODE(ST,  0x62),
        MEM_OPCODE(LDX, 0x61),


        [0x85] = &&OPCODE_CALL,
        [0x95] = &&OPCODE_RETURN,
    };

    goto bpf_start;

jump_instr:
    if (jump_cond) {
        instr += instr->offset;
        if (((intptr_t)instr >= (intptr_t)(bpf->application + bpf->application_len))
                || ((intptr_t)instr < (intptr_t)bpf->application)) {
            res = BPF_ILLEGAL_JUMP;
            goto exit;
        }
    }

    /* Intentionally falls through to select_instr */
select_instr:
    instr++;
bpf_start:
    bpf->instruction_count++;
    goto *_jumptable[instr->opcode];

    ALU(ADD,  +)
    ALU(SUB,  -)
    ALU(AND,  &)
    ALU(OR,   |)
    ALU(LSH, <<)
    ALU(RSH, >>)
    ALU(XOR,  ^)
    ALU(MUL,  *)
    ALU(DIV,  /)
    ALU(MOD,  %)

ALU64_NEG_REG:
    DST = -(int64_t)DST;
    CONT;

#if (CONFIG_BPF_ENABLE_ALU32)
ALU32_NEG_REG:
    DST = (int32_t)DST;
    CONT;

    /* MOV */
ALU32_MOV_IMM:
    DST = (uint32_t)IMM;
    CONT;
ALU32_MOV_REG:
    DST = (uint32_t)SRC;
    CONT;
#endif
ALU64_MOV_IMM:
    DST = (uint32_t)IMM;
    CONT;
ALU64_MOV_REG:
    DST = (uint32_t)SRC;
    CONT;

    /* Arithmetic shift */
ALU64_ARSH_REG:
    (*(int64_t*) &DST) >>= SRC;
    CONT;
ALU64_ARSH_IMM:
    (*(int64_t*) &DST) >>= IMM;
    CONT;
#if (CONFIG_BPF_ENABLE_ALU32)
ALU32_ARSH_REG:
    DST = (int32_t)DST >> SRC;
    CONT;
ALU32_ARSH_IMM:
    DST =  (int32_t)DST >> IMM;
    CONT;
#endif

MEM_LDDW_IMM:
    DST = (uint64_t)instr->immediate;
    instr++;
    DST |= ((uint64_t)(instr->immediate)) << 32;
    CONT;

#define MEM(SIZEOP, SIZE)                     \
      MEM_STX_##SIZEOP:                       \
          if (_check_store(bpf, sizeof(SIZE), DST + instr->offset) < 0) { \
              goto mem_error; \
          } \
          *(SIZE *)(uintptr_t)(DST + instr->offset) = SRC;   \
          CONT;                               \
      MEM_ST_##SIZEOP:                        \
          if (_check_store(bpf, sizeof(SIZE), DST + instr->offset) < 0) { \
              goto mem_error; \
          } \
          *(SIZE *)(uintptr_t)(DST + instr->offset) = IMM;   \
          CONT;                               \
      MEM_LDX_##SIZEOP:                       \
          if (_check_load(bpf, sizeof(SIZE), SRC + instr->offset) < 0) { \
              goto mem_error; \
          } \
          DST = *(const SIZE *)(uintptr_t)(SRC + instr->offset);   \
          CONT;

      MEM(BYTE, uint8_t)
      MEM(HALF, uint16_t)
      MEM(WORD, uint32_t)
      MEM(LONG, uint64_t)
#undef LDST


JUMP_ALWAYS:
    jump_cond = 1;
    CONT_JUMP;
    COND_JMP(ui, EQ, ==)
    COND_JMP(ui, GT, >)
    COND_JMP(ui, GE, >=)
    COND_JMP(ui, LT, <)
    COND_JMP(ui, LE, <=)
    COND_JMP(ui, SET, &)
    COND_JMP(ui, NE, !=)
    COND_JMP(i, SGT, >)
    COND_JMP(i, SGE, >=)
    COND_JMP(i, SLT, <)
    COND_JMP(i, SLE, <=)
OPCODE_CALL:
    {
        bpf_call_t call = _bpf_get_call(instr->immediate);
        if (call) {
                    regmap[0] = (*(call))(bpf,
                                          regmap[1],
                                          regmap[2],
                                          regmap[3],
                                          regmap[4],
                                          regmap[5]);
        }
        else {
            res = BPF_ILLEGAL_CALL;
            goto exit;
        }
    }
OPCODE_RETURN:
    goto exit;

mem_error:
    res = BPF_ILLEGAL_MEM;

exit:

    DEBUG("Number of instructions: %"PRIu32"\n", bpf->instruction_count);
    *result = regmap[0];
    return res;
}

