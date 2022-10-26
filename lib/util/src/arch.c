/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/arch.h>
#include <hse_util/assert.h>
#include <hse_util/compiler.h>
#include <hse_util/inttypes.h>

/* GCOV_EXCL_START */

#if __amd64__ && defined(SUPPORTS_ATTR_NOINLINE)

/* Use noinline to try to prevent LTO from inlining assembly.
 */
HSE_NOINLINE size_t
memlcp(const void *s1, const void *s2, size_t len)
{
    size_t rc;

    __asm__("movq   %1, %0      \n\t" /* rc = len;              */
            "cld                \n\t"
            "movq   %1, %%rcx   \n\t" /* rcx = len;             */
            "jrcxz  1f          \n\t" /* if (rcx == 0) goto 1;  */
            "repz               \n\t" /* while (rcx-- > 0 &&    */
            "cmpsb              \n\t" /*        *s1++ == *s2++) */
            "je     1f          \n\t" /* if (ZF) goto 1;        */
            "subq   %%rcx, %0   \n\t" /* rc -= rcx;             */
            "dec    %0          \n\t" /* rc -= 1;               */
            "1:                 \n\t"
            : "=r"(rc)
            : "r"(len), "D"(s1), "S"(s2)
            : "rcx", "memory");

    return rc;
}

/* Use noinline to try to prevent -flto from inlining assembly.
 */
HSE_NOINLINE size_t
memlcpq(const void *s1, const void *s2, size_t len)
{
    size_t rc;

    __asm__("movq   %1, %0      \n\t" /* rc = len;              */
            "shrq   $3, %0      \n\t" /* rc /= 8;               */
            "cld                \n\t"
            "movq   %0, %%rcx   \n\t" /* rcx = rc;              */
            "jrcxz  1f          \n\t" /* if (rcx == 0) goto 1;  */
            "repz               \n\t" /* while (rcx-- > 0 &&    */
            "cmpsq              \n\t" /*        *s1++ == *s2++) */
            "je     1f          \n\t" /* if (ZF) goto 1;        */
            "subq   %%rcx, %0   \n\t" /* rc -= rcx;             */
            "dec    %0          \n\t" /* rc -= 1;               */
            "1:                 \n\t"
            "shlq   $3, %0      \n\t" /* rc *= 8;               */
            : "=r"(rc)
            : "r"(len), "D"(s1), "S"(s2)
            : "rcx", "memory");

    return rc;
}

#else

size_t
memlcp(const void *s1, const void *s2, size_t len)
{
    const uint8_t *s1b = s1;
    const uint8_t *s2b = s2;
    const uint8_t *end = s1b + len;

    while (s1b < end && *s1b == *s2b++)
        ++s1b;

    return ((const char *)s1b - (const char *)s1);
}

size_t
memlcpq(const void *s1, const void *s2, size_t len)
{
    const uint64_t *s1q = s1;
    const uint64_t *s2q = s2;
    const uint64_t *end;

    end = s1q + (len / 8);

    while (s1q < end && *s1q == *s2q++)
        ++s1q;

    return ((const char *)s1q - (const char *)s1);
}

#endif

#if !__amd64__

/* We call hse_getcpu() frequently enough that the vDSO based getcpu call
 * is too expensive for our purposes.  To ameliorate the expense, we sample
 * getcpu() every so often on a per-thread basis.  This works fairly well
 * for s390x based VMs with low CPU counts, but likely we'll want to
 * revisit this for other architectures or use cases.
 */
#include <hse_util/atomic.h>
#include <syscall.h>

struct hse_getcpu_tls {
    ulong cnt HSE_ALIGNED(sizeof(ulong) * 2);
    uint  vcpu;
    uint  node;
};

static thread_local struct hse_getcpu_tls hse_getcpu_tls;

uint
hse_getcpu(uint *node)
{
#if __s390x__ || __ppc__
    if (hse_getcpu_tls.cnt++ % 32 == 0) {
        syscall(__NR_getcpu, &hse_getcpu_tls.vcpu, &hse_getcpu_tls.node, NULL);
    }
#else
    if (hse_getcpu_tls.cnt++ % 1024 == 0) {
        static atomic_uint hse_getcpu_gvcpu;

        /* Generate periodically changing fake vCPU and node IDs for architectures
         * not known to support a vDSO based getcpu().
         */
        hse_getcpu_tls.vcpu = atomic_inc_return(&hse_getcpu_gvcpu) % get_nprocs_conf();
        hse_getcpu_tls.node = hse_getcpu_tls.vcpu % 2;
    }
#endif

    if (node)
        *node = hse_getcpu_tls.node;

    return hse_getcpu_tls.vcpu;
}

#endif

/* GCOV_EXCL_STOP */
