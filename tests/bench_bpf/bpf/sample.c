#include <stdint.h>
#include "bpf/bpfapi/helpers.h"

int do_sample(void *ctx)
{
    int *num = ctx;
    *num += 8;
    const char fmt[] = "Test print %d\n";
    bpf_printf(fmt, *num);
    return *num;
}
