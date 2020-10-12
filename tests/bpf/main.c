/*
 * Copyright (C) 2020 Inria
 * Copyright (C) 2020 Koen Zandberg <koen@bergzand.net>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     tests
 * @{
 *
 * @file
 * @brief       Tests bpf virtual machine
 *
 * @author      Koen Zandberg <koen@bergzand.net>
 *
 * @}
 */
#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include "bpf.h"
#include "bpf/store.h"
#include "embUnit.h"

#include "sample.h"
#include "sample_storage.h"
#include "sample_saul.h"

#define BPF_SAMPLE_STORAGE_KEY_A  5
#define BPF_SAMPLE_STORAGE_KEY_B  15
#define BPF_SAMPLE_STORAGE_KEY_C  3
#define BPF_SAMPLE_STORAGE_KEY_SENSE  1

static uint8_t _bpf_stack[512];

static const uint8_t application[] = {
    0x18, 0x02, 0x00, 0x00, 0x54, 0x65, 0x73, 0x74, 0x00, 0x00, 0x00, 0x00, 0x20, 0x73, 0x74, 0x72, /* r2 = 824734340085208810x48, ll */
    0x7b, 0x2a, 0xc0, 0xff, 0x00, 0x00, 0x00, 0x00, /* *(u64, *)(r10, - 64) = r2 */
    0x7b, 0x2a, 0xe0, 0xff, 0x00, 0x00, 0x00, 0x00, /* *(u64, *)(r10, - 32) = r2 */
    0x18, 0x02, 0x00, 0x00, 0x69, 0x6e, 0x67, 0x20, 0x00, 0x00, 0x00, 0x00, 0x74, 0x6f, 0x20, 0x74, /* r2 = 836781065220492040x25, ll */
    0x7b, 0x2a, 0xc8, 0xff, 0x00, 0x00, 0x00, 0x00, /* *(u64, *)(r10, - 56) = r2 */
    0x7b, 0x2a, 0xe8, 0xff, 0x00, 0x00, 0x00, 0x00, /* *(u64, *)(r10, - 24) = r2 */
    0x18, 0x02, 0x00, 0x00, 0x72, 0x79, 0x20, 0x74, 0x00, 0x00, 0x00, 0x00, 0x68, 0x69, 0x6e, 0x67, /* r2 = 745301033069055010x30, ll */
    0x7b, 0x2a, 0xd0, 0xff, 0x00, 0x00, 0x00, 0x00, /* *(u64, *)(r10, - 48) = r2 */
    0x7b, 0x2a, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, /* *(u64, *)(r10, - 16) = r2 */
    0x18, 0x02, 0x00, 0x00, 0x73, 0x20, 0x6f, 0x75, 0x00, 0x00, 0x00, 0x00, 0x74, 0x00, 0x00, 0x00, /* r2 = 50018642340x11, ll */
    0x7b, 0x2a, 0xd8, 0xff, 0x00, 0x00, 0x00, 0x00, /* *(u64, *)(r10, - 40) = r2 */
    0x7b, 0x2a, 0xf8, 0xff, 0x00, 0x00, 0x00, 0x00, /* *(u64, *)(r10, - 8) = r2 */
    0x61, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* r1 = *(u32, *)(r1 + 0) */
    0x15, 0x01, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, /* if r1 == 0 goto +7 <LBB0_2> */
    0xbf, 0xa2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* r2 = r10, */
    0x07, 0x02, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, /* r2 += -64, */
    0x0f, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* r2 += r1 */
    0x71, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* r0 = *(u8 *)(r2 + 0) */
    0x67, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, /* r0 <<= 56, */
    0xc7, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, /* r0 s>>= 56, */
    0x05, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, /* goto +2 <LBB0_3> */

/* LBB0_2: */
    0xbf, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* r0 = r10 */
    0x07, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, /* r0 += -64 */

/* LBB0_3: */
    0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* exit */
};

static void _init(void)
{
    bpf_init();
}

static void tests_bpf_run1(void)
{
    bpf_t bpf = {
        .application = application,
        .application_len = sizeof(application),
        .stack = _bpf_stack,
        .stack_size = sizeof(_bpf_stack),
    };
    unsigned int ctx = 8;
    int64_t result = 0;
    TEST_ASSERT_EQUAL_INT(0, bpf_execute(&bpf, &ctx, sizeof(ctx), &result));
    TEST_ASSERT_EQUAL_INT(105, (int)result);
}

static void tests_bpf_run2(void)
{
    bpf_t bpf = {
        .application = sample_bin,
        .application_len = sizeof(sample_bin),
        .stack = _bpf_stack,
        .stack_size = sizeof(_bpf_stack),
    };
    unsigned int ctx = 8;
    int64_t result = 0;
    TEST_ASSERT_EQUAL_INT(0, bpf_execute(&bpf, &ctx, sizeof(ctx), &result));
    TEST_ASSERT_EQUAL_INT(16, (int)result);
}

static void tests_bpf_storage(void)
{
    bpf_t bpf = {
        .application = bpf_sample_storage_bin,
        .application_len = sizeof(bpf_sample_storage_bin),
        .stack = _bpf_stack,
        .stack_size = sizeof(_bpf_stack),
    };
    unsigned int ctx = 8;
    int64_t result = 0;
    TEST_ASSERT_EQUAL_INT(0, bpf_execute(&bpf, &ctx, sizeof(ctx), &result));

    uint32_t val;
    bpf_store_fetch_local(&bpf, BPF_SAMPLE_STORAGE_KEY_A, &val);
    TEST_ASSERT_EQUAL_INT(1, val);

    bpf_store_fetch_local(&bpf, BPF_SAMPLE_STORAGE_KEY_B, &val);
    TEST_ASSERT_EQUAL_INT(2, val);

    bpf_store_fetch_local(&bpf, BPF_SAMPLE_STORAGE_KEY_C, &val);
    TEST_ASSERT_EQUAL_INT(3, val);

    /* Second execution */
    TEST_ASSERT_EQUAL_INT(0, bpf_execute(&bpf, &ctx, sizeof(ctx), &result));
    bpf_store_fetch_local(&bpf, BPF_SAMPLE_STORAGE_KEY_A, &val);
    TEST_ASSERT_EQUAL_INT(2, val);
    bpf_store_fetch_local(&bpf, BPF_SAMPLE_STORAGE_KEY_B, &val);
    TEST_ASSERT_EQUAL_INT(6, val);
    bpf_store_fetch_local(&bpf, BPF_SAMPLE_STORAGE_KEY_C, &val);
    TEST_ASSERT_EQUAL_INT(8, val);
}

static void tests_bpf_saul(void)
{
    bpf_t bpf = {
        .application = bpf_sample_saul_bin,
        .application_len = sizeof(bpf_sample_saul_bin),
        .stack = _bpf_stack,
        .stack_size = sizeof(_bpf_stack),
    };
    unsigned int ctx = 0;
    int64_t result = 0;
    TEST_ASSERT_EQUAL_INT(0, bpf_execute(&bpf, &ctx, sizeof(ctx), &result));

    TEST_ASSERT_EQUAL_INT(0, result);

    uint32_t val = 0;
    bpf_store_fetch_local(&bpf, BPF_SAMPLE_STORAGE_KEY_SENSE, &val);
    printf("BPF saul val: %"PRIu32"\n", val);
}


Test *tests_bpf(void)
{
    EMB_UNIT_TESTFIXTURES(fixtures) {
        new_TestFixture(tests_bpf_run1),
        new_TestFixture(tests_bpf_run2),
        new_TestFixture(tests_bpf_storage),
        new_TestFixture(tests_bpf_saul),
    };

    EMB_UNIT_TESTCALLER(bpf_tests, _init, NULL, fixtures);
    return (Test*)&bpf_tests;
}

int main(void)
{
    TESTS_START();
    TESTS_RUN(tests_bpf());
    TESTS_END();

    return 0;
}
