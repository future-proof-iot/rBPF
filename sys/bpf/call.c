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
#include <stdio.h>

#include "bpf.h"
#include "bpf/instruction.h"

uint32_t bpf_vm_printf(uint32_t fmt, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4)
{
    return printf((char*)(uintptr_t)fmt, a1, a2, a3, a4);
}
