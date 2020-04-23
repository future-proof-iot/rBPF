/*
 * Copyright (C) 2020 Inria
 * Copyright (C) 2020 Koen Zandberg <koen@bergzand.net>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdint.h>
#include <stdbool.h>
#include "assert.h"
#include "bpf.h"
#include "bpf/store.h"

extern int bpf_run(bpf_t *bpf, const void *ctx, int64_t *result);

static bpf_hook_t *_hooks[BPF_HOOK_NUM] = { 0 };

static bool _continue(bpf_hook_t *hook, int64_t *res)
{
    switch(hook->policy) {
        case BPF_POLICY_CONTINUE:
            return true;
        case BPF_POLICY_SINGLE:
            return false;
        case BPF_POLICY_ABORT_ON_NEGATIVE:
            return (*res < 0) ? false : true;
        case BPF_POLICY_ABORT_ON_POSITIVE:
            return (*res > 0) ? false : true;
    }
    return true;
}

int bpf_execute(bpf_t *bpf, void *ctx, int64_t *result)
{
    return bpf_run(bpf, ctx, result);
}

static void _register(bpf_hook_t **install_hook, bpf_hook_t *new)
{
    new->next = *install_hook;
    *install_hook = new;
}

void bpf_init(void)
{
    bpf_store_init();
}

int bpf_hook_install(bpf_hook_t *hook, bpf_hook_trigger_t trigger) {
    assert(trigger < BPF_HOOK_NUM);
    _register(&_hooks[trigger], hook);
    return 0;
}

int bpf_hook_execute(bpf_hook_trigger_t trigger, void *ctx, int64_t *script_res)
{
    assert(trigger < BPF_HOOK_NUM);

    int res = BPF_OK;

    for (bpf_hook_t *h = _hooks[trigger]; h; h = h->next) {
        res = bpf_execute(h->application, ctx, script_res);
        h->executions++;
        if ((res == BPF_OK) && !_continue(h, script_res)) {
            break;
        }
    }
    return res;
}
