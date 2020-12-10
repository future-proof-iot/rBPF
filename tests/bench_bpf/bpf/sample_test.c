#include <stdint.h>
#include "bpf/bpfapi/helpers.h"

#define BPF_SAMPLE_STORAGE_KEY_A  1

int do_sample(void *ctx)
{
    uint32_t a;
    bpf_fetch_local(BPF_SAMPLE_STORAGE_KEY_A, &a);
    a++;
    bpf_store_local(BPF_SAMPLE_STORAGE_KEY_A, a);
    return a;
}
