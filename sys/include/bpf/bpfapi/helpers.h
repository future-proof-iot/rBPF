/*
 * Copyright (C) 2020 Inria
 * Copyright (C) 2020 Koen Zandberg <koen@bergzand.net>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef BPF_BPFAPI_HELPERS_H
#define BPF_BPFAPI_HELPERS_H

#include <stdint.h>
#include "bpf/shared.h"

#ifdef __cplusplus
extern "C" {
#endif

static void *(*bpf_printf)(const char *fmt, ...) = (void *) BPF_FUNC_BPF_PRINTF;

#ifdef __cplusplus
}
#endif
#endif /* BPF_APPLICATION_CALL_H */
