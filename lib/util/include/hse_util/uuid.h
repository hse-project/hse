/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_UUID_H
#define HSE_PLATFORM_UUID_H

#include <uuid/uuid.h>

#define HSE_UUID_SIZE 16

struct hse_uuid {
    unsigned char uuid[HSE_UUID_SIZE];
};

#if defined(HSE_DISTRO_EL75)
/* in rhel 7.4, type uuid_be is defined in /usr/include/linux - but not so
 * in rhel 7.5.  But the kernel's nvme.h requires is either way.
 */
typedef uuid_t uuid_be;
#endif

static inline void
hse_unparse_uuid(const struct hse_uuid *uuid, char *out)
{
    uuid_unparse(uuid->uuid, out);
}

static inline int
hse_parse_uuid(const char *in, struct hse_uuid *out)
{
    return uuid_parse(in, out->uuid);
}

static inline void
hse_generate_uuid(struct hse_uuid *uuid)
{
    uuid_generate(uuid->uuid);
}

static inline void
hse_uuid_copy(struct hse_uuid *u_dst, struct hse_uuid *u_src)
{
    uuid_copy(u_dst->uuid, u_src->uuid);
}

static inline int
hse_uuid_compare(struct hse_uuid *uuid1, struct hse_uuid *uuid2)
{
    return uuid_compare(uuid1->uuid, uuid2->uuid);
}

static inline void
hse_uuid_clear(struct hse_uuid *uuid)
{
    uuid_clear(uuid->uuid);
}

static inline int
hse_uuid_is_null(struct hse_uuid *uuid)
{
    return uuid_is_null(uuid->uuid);
}

#endif
