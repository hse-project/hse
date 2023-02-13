/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#include <hse/util/arch.h>

/* GCOV_EXCL_START */

#if !__amd64__

/* We call hse_getcpu() frequently enough that the vDSO based getcpu call
 * is too expensive for our purposes.  To ameliorate the expense, we sample
 * getcpu() every so often on a per-thread basis.  This works fairly well
 * for s390x based VMs with low CPU counts, but likely we'll want to
 * revisit this for other architectures or use cases.
 */
#include <unistd.h>

#include <sys/syscall.h>

#include <hse/util/atomic.h>

struct hse_getcpu_tls {
    ulong cnt HSE_ALIGNED(sizeof(ulong) * 2);
    uint vcpu;
    uint node;
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
