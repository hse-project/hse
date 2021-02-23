/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_OMF_H
#define HSE_PLATFORM_OMF_H

#include <hse_util/byteorder.h>
#include <hse_util/inttypes.h>
#include <hse_util/bug.h>

/* The following two macros exist solely to enable the OMF_SETGET macros to
 * work on 8 bit members as well as 16, 32 and 64 bit members.
 */
#define le8_to_cpu(x) (x)
#define cpu_to_le8(x) (x)

/* Helper macro to define set/get methods for 8, 16, 32 or 64 bit
 * scalar OMF struct members.
 */
#define OMF_SETGET(type, member, bits) OMF_SETGET2(type, member, bits, member)

#define OMF_SETGET2(type, member, bits, name)                          \
    static HSE_ALWAYS_INLINE u##bits omf_##name(const type *s)         \
    {                                                                  \
        BUILD_BUG_ON(sizeof(((type *)0)->member) * 8 != (bits));       \
        return le##bits##_to_cpu(s->member);                           \
    }                                                                  \
    static HSE_ALWAYS_INLINE void omf_set_##name(type *s, u##bits val) \
    {                                                                  \
        s->member = cpu_to_le##bits(val);                              \
    }

/* Helper macro to define set/get methods for character strings
 * embedded in OMF structures.
 */
#define OMF_SETGET_CHBUF(type, member) OMF_SETGET_CHBUF2(type, member, member)

#define OMF_SETGET_CHBUF2(type, member, name)                              \
    static inline void omf_set_##name(type *s, const void *p, size_t plen) \
    {                                                                      \
        size_t len = sizeof(((type *)0)->member);                          \
        memcpy(s->member, p, len < plen ? len : plen);                     \
    }                                                                      \
    static inline void omf_##name(const type *s, void *p, size_t plen)     \
    {                                                                      \
        size_t len = sizeof(((type *)0)->member);                          \
        memcpy(p, s->member, len < plen ? len : plen);                     \
    }

#define OMF_GET_VER(type, member, bits, ver)                             \
    static HSE_ALWAYS_INLINE u##bits omf_##member##_##ver(const type *s) \
    {                                                                    \
        BUILD_BUG_ON(sizeof(((type *)0)->member) * 8 != (bits));         \
        return le##bits##_to_cpu(s->member);                             \
    }

#define OMF_GET_CHBUF_VER(type, member, ver)                                     \
    static inline void omf_##member##_##ver(const type *s, void *p, size_t plen) \
    {                                                                            \
        size_t len = sizeof(((type *)0)->member);                                \
        memcpy(p, s->member, len < plen ? len : plen);                           \
    }

#endif /* HSE_PLATFORM_OMF_H */
