/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_OMF_H
#define HSE_PLATFORM_OMF_H

#include <hse/util/byteorder.h>
#include <hse/util/inttypes.h>

/* Write to media in host byte order by default...
 */
#ifndef HSE_OMF_BYTE_ORDER
#define HSE_OMF_BYTE_ORDER      __BYTE_ORDER__
#endif

/* Helper macro to define set/get methods for 8, 16, 32 or 64 bit
 * scalar OMF struct members.
 */
#if HSE_OMF_BYTE_ORDER == __ORDER_BIG_ENDIAN__
#define cpu_to_omf64(_x)    cpu_to_be64(_x)
#define omf64_to_cpu(_x)    be64_to_cpu(_x)

#define cpu_to_omf32(_x)    cpu_to_be32(_x)
#define omf32_to_cpu(_x)    be32_to_cpu(_x)

#define be8_to_cpu(_x)      (_x)
#define cpu_to_be8(_x)      (_x)

#define OMF_SETGET(_type, _member, _bits)                               \
    static HSE_ALWAYS_INLINE u ## _bits                                 \
    omf_ ## _member(const _type *s)                                     \
    {                                                                   \
        static_assert(sizeof(((_type *)0)->_member) * 8 == (_bits),     \
                      "invalid size");                                  \
        return be ## _bits ## _to_cpu(s->_member);                      \
    }                                                                   \
    static HSE_ALWAYS_INLINE void                                       \
    omf_set_ ## _member(_type *s, u ## _bits val)                       \
    {                                                                   \
        s->_member = cpu_to_be ## _bits(val);                           \
    }

#define OMF_GET_VER(_type, _member, _bits, _ver)                        \
    static HSE_ALWAYS_INLINE u ## _bits                                 \
    omf_ ## _member ## _ ## _ver(const _type *s)                        \
    {                                                                   \
        static_assert(sizeof(((_type *)0)->_member) * 8 == (_bits),     \
                      "invalid size");                                  \
        return be ## _bits ## _to_cpu(s->_member);                      \
    }

#else
#define cpu_to_omf64(_x)    cpu_to_le64(_x)
#define omf64_to_cpu(_x)    le64_to_cpu(_x)

#define cpu_to_omf32(_x)    cpu_to_le32(_x)
#define omf32_to_cpu(_x)    le32_to_cpu(_x)

#define le8_to_cpu(_x)      (_x)
#define cpu_to_le8(_x)      (_x)

#define OMF_SETGET(_type, _member, _bits)                               \
    static HSE_ALWAYS_INLINE u ## _bits                                 \
    omf_ ## _member(const _type *s)                                     \
    {                                                                   \
        static_assert(sizeof(((_type *)0)->_member) * 8 == (_bits),     \
                      "invalid size");                                  \
        return le ## _bits ## _to_cpu(s->_member);                      \
    }                                                                   \
    static HSE_ALWAYS_INLINE void                                       \
    omf_set_ ## _member(_type *s, u ## _bits val)                       \
    {                                                                   \
        s->_member = cpu_to_le ## _bits(val);                           \
    }

#define OMF_GET_VER(_type, _member, _bits, _ver)                        \
    static HSE_ALWAYS_INLINE u ## _bits                                 \
    omf_ ## _member ## _ ## _ver(const _type *s)                        \
    {                                                                   \
        static_assert(sizeof(((_type *)0)->_member) * 8 == (_bits),     \
                      "unexpected size");                               \
        return le ## _bits ## _to_cpu(s->_member);                      \
    }

#endif

/* Helper macro to define set/get methods for character strings
 * embedded in OMF structures.
 */
#define OMF_SETGET_CHBUF(_type, _member)                        \
    static inline void                                          \
    omf_set_ ## _member(_type *s, const void *p, size_t plen)   \
    {                                                           \
        size_t len = sizeof(((_type *)0)->_member);             \
        memcpy(s->_member, p, len < plen ? len : plen);         \
    }                                                           \
    static inline void                                          \
    omf_ ## _member(const _type *s, void *p, size_t plen)       \
    {                                                           \
        size_t len = sizeof(((_type *)0)->_member);             \
        memcpy(p, s->_member, len < plen ? len : plen);         \
    }

#define OMF_GET_CHBUF_VER(_type, _member, _ver)                         \
    static inline void                                                  \
    omf_## _member ## _ ## _ver(const _type *s, void *p, size_t plen)   \
    {                                                                   \
        size_t len = sizeof(((_type *)0)->_member);                     \
        memcpy(p, s->_member, len < plen ? len : plen);                 \
    }

#endif /* HSE_PLATFORM_OMF_H */
