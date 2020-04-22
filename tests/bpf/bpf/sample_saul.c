#include <stdint.h>
#include "bpf/bpfapi/helpers.h"

#define BPF_SAMPLE_STORAGE_KEY_SENSE    1

int read_button(void *ctx)
{
    (void)ctx;

    bpf_saul_reg_t *reg = bpf_saul_reg_find_nth(1);

    phydat_t data;

    int res = bpf_saul_reg_read(reg, &data);

    if (res) {
        bpf_store_local(BPF_SAMPLE_STORAGE_KEY_SENSE, data.val[0]);
    }

    return 0;
}
