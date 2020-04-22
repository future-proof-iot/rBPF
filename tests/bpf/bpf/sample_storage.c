#include <stdint.h>
#include "bpf/bpfapi/helpers.h"

#define BPF_SAMPLE_STORAGE_KEY_A  5
#define BPF_SAMPLE_STORAGE_KEY_B  15
#define BPF_SAMPLE_STORAGE_KEY_C  3

int do_sample(void *ctx)
{
    (void)ctx;

    uint32_t a;
    bpf_fetch_local(BPF_SAMPLE_STORAGE_KEY_A, &a);
    a++;
    bpf_store_local(BPF_SAMPLE_STORAGE_KEY_A, a);

    uint32_t b;
    bpf_fetch_local(BPF_SAMPLE_STORAGE_KEY_B, &b);

    b += 1;
    b *= 2;

    bpf_store_local(BPF_SAMPLE_STORAGE_KEY_B, b);

    uint32_t c = a + b;
    bpf_store_local(BPF_SAMPLE_STORAGE_KEY_C, c);
    return 0;
}
