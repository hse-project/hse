/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <byteswap.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>

#include <hse/util/platform.h>
#include <hse/util/slab.h>
#include <hse/util/xrand.h>

#include <hse/ikvdb/omf_kmd.h>
#include <hse/ikvdb/limits.h>

#define GiB 1024 * 1024 * 1024
#define MiB 1024 * 1024

const size_t mem_size = 1ull * GiB;
const unsigned long randc = 16ull * MiB;
void *mem;
uint64_t *randv;
uint32_t seed;

int failed;

#define ENCODER(NAME) \
    static inline __attribute__((always_inline)) void NAME(void *base, size_t *off, uint64_t val)

#define DECODER(NAME) \
    static inline __attribute__((always_inline)) uint64_t NAME(const void *base, size_t *off)


/*****************************************************************
 *
 * Native codecs
 *
 */

ENCODER(encode_n8)
{
    uint8_t *p = base + *off;
    assert(val <= UINT8_MAX);
    *off += sizeof(*p);
    *p = (uint8_t)val;
}
ENCODER(encode_n16)
{
    uint16_t *p = base + *off;
    assert(val <= UINT16_MAX);
    *off += sizeof(*p);
    *p = (uint16_t)val;
}
ENCODER(encode_n32)
{
    uint32_t *p = base + *off;
    assert(val <= UINT32_MAX);
    *off += sizeof(*p);
    *p = (uint32_t)val;
}
ENCODER(encode_n64)
{
    uint64_t *p = base + *off;
    assert(val <= UINT64_MAX);
    *off += sizeof(*p);
    *p = (uint64_t)val;
}

DECODER(decode_n8)
{
    const uint8_t *p = base + *off;
    *off += sizeof(*p);
    return *p;
}
DECODER(decode_n16)
{
    const uint16_t *p = base + *off;
    *off += sizeof(*p);
    return *p;
}
DECODER(decode_n32)
{
    const uint32_t *p = base + *off;
    *off += sizeof(*p);
    return *p;
}
DECODER(decode_n64)
{
    const uint64_t *p = base + *off;
    *off += sizeof(*p);
    return *p;
}

/*****************************************************************
 *
 * BE/LE codecs
 *
 */

ENCODER(encode_be16)
{
    uint16_t *p = base + *off;
    assert(val <= UINT16_MAX);
    *off += sizeof(*p);
    *p = htobe16((uint16_t)val);
}
ENCODER(encode_le16)
{
    uint16_t *p = base + *off;
    assert(val <= UINT16_MAX);
    *off += sizeof(*p);
    *p = htole16((uint16_t)val);
}

ENCODER(encode_be32)
{
    uint32_t *p = base + *off;
    assert(val <= UINT32_MAX);
    *off += sizeof(*p);
    *p = htobe32((uint32_t)val);
}
ENCODER(encode_le32)
{
    uint32_t *p = base + *off;
    assert(val <= UINT32_MAX);
    *off += sizeof(*p);
    *p = htole32((uint32_t)val);
}

ENCODER(encode_be64)
{
    uint64_t *p = base + *off;
    assert(val <= UINT64_MAX);
    *off += sizeof(*p);
    *p = htobe64((uint64_t)val);
}
ENCODER(encode_le64)
{
    uint64_t *p = base + *off;
    assert(val <= UINT64_MAX);
    *off += sizeof(*p);
    *p = htole64((uint64_t)val);
}

DECODER(decode_be16)
{
    const uint16_t *p = base + *off;
    *off += sizeof(*p);
    return be16toh(*p);
}
DECODER(decode_le16)
{
    const uint16_t *p = base + *off;
    *off += sizeof(*p);
    return le16toh(*p);
}

DECODER(decode_be32)
{
    const uint32_t *p = base + *off;
    *off += sizeof(*p);
    return be32toh(*p);
}
DECODER(decode_le32)
{
    const uint32_t *p = base + *off;
    *off += sizeof(*p);
    return le32toh(*p);
}

DECODER(decode_be64)
{
    const uint64_t *p = base + *off;
    *off += sizeof(*p);
    return be64toh(*p);
}
DECODER(decode_le64)
{
    const uint64_t *p = base + *off;
    *off += sizeof(*p);
    return le64toh(*p);
}


#define CODEC(NAME,ENC_FN,DEC_FN)                               \
    void NAME(                                                  \
        bool encode,                                            \
        uint64_t *ops_out,                                      \
        uint64_t *bytes_out,                                    \
        uint64_t *xor_out)                                      \
    {                                                           \
        uint64_t xor = 0;                                       \
        uint64_t off = 0;                                       \
        uint64_t ops = 0;                                       \
        uint64_t val;                                           \
                                                                \
        if (encode) {                                           \
                                                                \
            while (off + 128 < mem_size) {                      \
                val = randv[(randc - 1) & ops];                 \
                xor ^= val;                                     \
                ENC_FN(mem, &off, val);                         \
                ops++;                                          \
            }                                                   \
                                                                \
        } else {                                                \
                                                                \
            while (off + 128 < mem_size) {                      \
                val = DEC_FN(mem, &off);                        \
                xor ^= val;                                     \
                assert(randv[(randc - 1) & ops] == val);        \
                assert(off < mem_size);                         \
                ops++;                                          \
            }                                                   \
        }                                                       \
                                                                \
        *ops_out = ops;                                         \
        *bytes_out = off;                                       \
        *xor_out = xor;                                         \
    }

CODEC(codec_n8,  encode_n8,  decode_n8);
CODEC(codec_n16, encode_n16, decode_n16);
CODEC(codec_n32, encode_n32, decode_n32);
CODEC(codec_n64, encode_n64, decode_n64);

CODEC(codec_be16, encode_be16, decode_be16);
CODEC(codec_be32, encode_be32, decode_be32);
CODEC(codec_be64, encode_be64, decode_be64);

CODEC(codec_le16, encode_le16, decode_le16);
CODEC(codec_le32, encode_le32, decode_le32);
CODEC(codec_le64, encode_le64, decode_le64);

CODEC(codec_hg16_32k,   encode_hg16_32k,   decode_hg16_32k);
CODEC(codec_hg24_4m,    encode_hg24_4m,    decode_hg24_4m);
CODEC(codec_hg32_1024m, encode_hg32_1024m, decode_hg32_1024m);
CODEC(codec_hg64,       encode_hg64,       decode_hg64);

CODEC(codec_varint,     encode_varint,     decode_varint);

void
report(
    const char *   name,
    unsigned long  op_count,
    unsigned long  byte_count,
    struct timeval enc,
    struct timeval dec)
{
    static int header;

    double M = 1024 * 1024;
    double enc1 = enc.tv_sec + enc.tv_usec * 1e-6;
    double dec1 = dec.tv_sec + dec.tv_usec * 1e-6;
    double ops = op_count / M;
    double bytes = byte_count / M;

    if (!header) {
        int len = strlen(name);

        header = 1;
        printf("\n# Encoder performance (values scaled by 1024*1024)\n");

        printf(
            "%-*s  %8s  %8s  %8s  %8s  %8s  %8s\n",
            len,
            "",
            "",
            "",
            "Encode",
            "Encode",
            "Decode",
            "Decode");

        printf(
            "%-*s  %8s  %8s  %8s  %8s  %8s  %8s\n",
            len,
            "Test",
            "Ops",
            "Bytes",
            "ops/s",
            "bytes/s",
            "ops/s",
            "bytes/s");
        printf(
            "%-*s  %.8s  %.8s  %.8s  %.8s  %.8s  %.8s\n",
            len,
            "-----------------",
            "-----------------",
            "-----------------",
            "-----------------",
            "-----------------",
            "-----------------",
            "-----------------");
    }
    printf(
        "%s  %8.0f  %8.0f  %8.0f  %8.0f  %8.0f  %8.0f\n",
        name,
        ops,
        bytes,
        ops / enc1,
        bytes / enc1,
        ops / dec1,
        bytes / dec1);
}

static inline void
test(const char *NAME,
    void (*codec)(bool encode, uint64_t *ops_inout, uint64_t *bytes_out, uint64_t *xor_out),
    uint64_t MAX_MASK,
    int MODE)
{
    struct timeval  prev, now, diff1, diff2;
    struct xrand xr;

    uint64_t  xor1 = 0, xor2 = 0;
    uint64_t  ops1 = 0, ops2 = 0;
    uint64_t  bytes1 = 0, bytes2 = 0;
    char tnam[256];
    char modestr[32];
    uint64_t mode_mask;
    int mode;

    xrand_init(&xr, seed);

    /* mask: 3f, 3fff, 3fffff, etc */
    mode = (1 <= MODE && MODE <= 8) ? MODE : 8;
    snprintf(modestr, sizeof(modestr), "%dbytes", mode);

    mode_mask = (1LL << ((mode)*8 - 2)) - 1;
    for (uint64_t i = 0; i < randc; i++)
        randv[i] = xrand64(&xr) & (MAX_MASK)&mode_mask;

    gettimeofday(&prev, NULL);
    codec(true, &ops1, &bytes1, &xor1);
    gettimeofday(&now, NULL);
    timersub(&now, &prev, &diff1);

    gettimeofday(&prev, NULL);
    codec(false, &ops2, &bytes2, &xor2);
    gettimeofday(&now, NULL);
    timersub(&now, &prev, &diff2);

    snprintf(tnam, sizeof(tnam), "%-10s %-8s", NAME, modestr);
    report(tnam, ops1, bytes1, diff1, diff2);

    if (ops1 == 0) {
        failed = 1;
        printf("%s: BUG: no values encoded\n", NAME);
    }
    else if (ops1 != ops2) {
        failed = 1;
        printf("%s: BUG: encode ops != decode ops: %lu != %lu\n", NAME, ops1, ops2);
    }
    else if (bytes1 != bytes2) {
        failed = 1;
        printf("%s: BUG: encode bytes != decode bytes: %lu != %lu\n", NAME, bytes1, bytes2);
    }
    else if (xor1 != xor2) {
        failed = 1;
        printf("%s: BUG: XOR mismatch: %lx ! = %lx\n", NAME, xor1, xor2);
    }
}

void
run_encoder_perf(uint32_t seed)
{
    test("warmup", codec_n8, UINT8_MAX, 1);
    printf("\n");

    test("native8",  codec_n8,  UINT8_MAX,  1);
    test("native16", codec_n16, UINT16_MAX, 2);
    test("native32", codec_n32, UINT32_MAX, 4);
    test("native64", codec_n64, UINT64_MAX, 8);
    printf("\n");

    test("be16", codec_be16, UINT16_MAX, 2);
    test("be32", codec_be32, UINT32_MAX, 4);
    test("be64", codec_be64, UINT64_MAX, 8);
    printf("\n");

    test("le16", codec_le16, UINT16_MAX, 2);
    test("le32", codec_le32, UINT32_MAX, 4);
    test("le64", codec_le64, UINT64_MAX, 8);
    printf("\n");

    test("hg16_32k", codec_hg16_32k, HG16_32K_MAX, 1);
    test("hg16_32k", codec_hg16_32k, HG16_32K_MAX, 2);
    printf("\n");

    test("hg24_4m", codec_hg24_4m, HG24_4M_MAX, 1);
    test("hg24_4m", codec_hg24_4m, HG24_4M_MAX, 2);
    test("hg24_4m", codec_hg24_4m, HG24_4M_MAX, 3);
    printf("\n");

    test("hg32_1024m", codec_hg32_1024m, HG32_1024M_MAX, 1);
    test("hg32_1024m", codec_hg32_1024m, HG32_1024M_MAX, 2);
    test("hg32_1024m", codec_hg32_1024m, HG32_1024M_MAX, 3);
    test("hg32_1024m", codec_hg32_1024m, HG32_1024M_MAX, 4);
    printf("\n");

    test("hg64", codec_hg64, HG64_MAX, 2);
    test("hg64", codec_hg64, HG64_MAX, 4);
    test("hg64", codec_hg64, HG64_MAX, 6);
    test("hg64", codec_hg64, HG64_MAX, 8);
    printf("\n");

    test("varint", codec_varint, UINT64_MAX, 1);
    test("varint", codec_varint, UINT64_MAX, 2);
    test("varint", codec_varint, UINT64_MAX, 3);
    test("varint", codec_varint, UINT64_MAX, 4);
    test("varint", codec_varint, UINT64_MAX, 5);
    test("varint", codec_varint, UINT64_MAX, 6);
    test("varint", codec_varint, UINT64_MAX, 7);
    test("varint", codec_varint, UINT64_MAX, 8);
    printf("\n");
}

struct kmd_test_stats {
    uint64_t nbytes, nkeys, nseqs, nvals, nivals, nzvals, ntombs, nptombs;
};

enum test_enc { enc_short, enc_med, enc_long };
enum test_mix { tombs_only, vals_only, mixed };

static const char *
test_enc_name(enum test_enc enc)
{
    switch (enc) {
        case enc_short:
            return "short";
        case enc_med:
            return "med";
        case enc_long:
            return "long";
    }
    return "unknown";
}

struct kmd_test_profile {
    struct xrand    xr;
    unsigned        max_keys;
    unsigned        max_ents_per_key;
    enum test_enc   enc;
    enum test_mix   mix;
};

unsigned
tp_next_count(struct kmd_test_profile *tp)
{
    return (xrand64(&tp->xr) % tp->max_ents_per_key) + 1;
}

void
tp_next_entry(
    struct kmd_test_profile *tp,
    enum kmd_vtype *         vtype,
    uint64_t *               seq,
    uint *                   vbidx,
    uint *                   vboff,
    const void **            vdata,
    uint *                   vlen,
    uint *                   clen)
{
    static char valbuf[CN_SMALL_VALUE_THRESHOLD] = { 17, 23, 42, 211, 164, 96, 11, 7 };
    uint32_t    rv;

    *seq = xrand64(&tp->xr) & HG64_MAX;

    if (tp->enc == enc_short)
        *seq &= 0x3f;
    else if (tp->enc == enc_med)
        *seq &= 0x3fff;

    rv = xrand64(&tp->xr);

    if (tp->mix == vals_only)
        goto value;

    if (rv < 3 * (UINT32_MAX / 100)) {
        *vtype = VTYPE_ZVAL;
        *vlen = 0;
        return;
    }

    if (rv < 5 * (UINT32_MAX / 100)) {
        *vtype = VTYPE_IVAL;
        *vdata = valbuf;
        *vlen = 1 + xrand64(&tp->xr) % CN_SMALL_VALUE_THRESHOLD;
        return;
    }

    if (rv < 7 * (UINT32_MAX / 100)) {
        *vtype = VTYPE_TOMB;
        return;
    }

    if (rv < 10 * (UINT32_MAX / 100)) {
        *vtype = VTYPE_PTOMB;
        return;
    }

    if (tp->mix == tombs_only) {
        /* a mix of tombs */
        *vtype = VTYPE_TOMB;
        return;
    }

value:
    *vtype = VTYPE_UCVAL;
    *vboff = xrand64(&tp->xr);
    *vbidx = xrand64(&tp->xr) & HG16_32K_MAX;
    *vlen = xrand64(&tp->xr) & HG32_1024M_MAX;
    *clen = 0;
    if (*vlen <= CN_SMALL_VALUE_THRESHOLD)
        *vlen = CN_SMALL_VALUE_THRESHOLD;
    if (tp->enc == enc_short) {
        *vbidx &= 0x3f;
        *vlen &= 0x7f;
    } else if (tp->enc == enc_med) {
        *vbidx &= 0x3f;
        *vlen &= 0xfff;
    }
    if (xrand64(&tp->xr) % 100 < 10) {
        *vtype = VTYPE_CVAL;
        *clen = *vlen / 2;
        if (!*clen)
            *clen = 1;
    }
}

void
run_kmd_write_perf(struct kmd_test_stats *s)
{
    uint64_t off, seq, rx, rval;
    unsigned count;
    uint     vbidx, vboff, vlen;

    off = 0;
    rx = 0;

    while (off + 1024 <= mem_size) {

        rval = randv[(randc - 1) & rx++];
        count = (rval & 3) + 1;
        seq = rval & 0xfff;

        s->nkeys++;
        s->nseqs += count;

        kmd_set_count(mem, &off, count);

        if (count == 4) {
            kmd_add_tomb(mem, &off, seq++);
            s->ntombs++;
            count = 3;
        }

        vbidx = (rval >> 16) & 0xf;
        vboff = (rval >> 32);
        vlen = (rval >> 24) & 0xff;

        s->nvals += count;
        while (count-- > 0)
            kmd_add_val(mem, &off, seq++, vbidx, vboff, vlen);
    }

    kmd_set_count(mem, &off, 0);
    s->nbytes = off;
}

void
run_kmd_read_perf(struct kmd_test_stats *s)
{
    uint64_t       off, seq, rx, rval;
    unsigned       i, count;
    enum kmd_vtype vtype;
    uint           vbidx, vboff, vlen, clen;
    const void *   vdata;

    off = 0;
    rx = 0;

    while (true) {
        unsigned exp_count HSE_MAYBE_UNUSED;
        uint64_t exp_seq HSE_MAYBE_UNUSED;

        rval = randv[(randc - 1) & rx++];
        exp_count = (rval & 3) + 1;
        exp_seq = rval & 0xfff;

        count = kmd_count(mem, &off);
        if (count == 0)
            break;

        assert(count == exp_count);

        s->nkeys++;
        s->nseqs += count;

        for (i = 0; i < count; i++) {
            kmd_type_seq(mem, &off, &vtype, &seq);
            assert(exp_seq + i == seq);
            switch (vtype) {
                case VTYPE_IVAL:
                    kmd_ival(mem, &off, &vdata, &vlen);
                    s->nvals++;
                    break;
                case VTYPE_UCVAL:
                    kmd_val(mem, &off, &vbidx, &vboff, &vlen);
                    s->nvals++;
                    break;
                case VTYPE_CVAL:
                    kmd_cval(mem, &off, &vbidx, &vboff, &vlen, &clen);
                    s->nvals++;
                    break;
                case VTYPE_ZVAL:
                    s->nvals++;
                    break;
                case VTYPE_PTOMB:
                case VTYPE_TOMB:
                    s->ntombs++;
                    break;
            }
        }
    }
    s->nbytes = off;
}

void
run_kmd_tp(struct kmd_test_profile *tp, struct kmd_test_stats *s, bool writing)
{
    uint64_t       off, seq;
    unsigned       count, actual_count, may_need;
    enum kmd_vtype vtype;
    uint           i, vbidx, vboff, vlen, clen;
    const void *   vdata;

    off = 0;

    /* If max_keys is 0, stop when buffer is full */
    while (tp->max_keys == 0 || s->nkeys < tp->max_keys) {

        if (writing) {
            may_need = kmd_storage_max(tp->max_ents_per_key);
            if (off + may_need > mem_size)
                break;
        }

        count = tp_next_count(tp);
        if (writing) {
            kmd_set_count(mem, &off, count);
        } else {
            actual_count = kmd_count(mem, &off);
            if (actual_count == 0)
                break;
            assert(actual_count == count);
        }

        s->nkeys++;
        s->nseqs += count;
        for (i = 0; i < count; i++) {
            tp_next_entry(tp, &vtype, &seq, &vbidx, &vboff, &vdata, &vlen, &clen);
            switch (vtype) {
                case VTYPE_TOMB:
                    s->ntombs++;
                    break;
                case VTYPE_PTOMB:
                    s->nptombs++;
                    break;
                case VTYPE_ZVAL:
                    s->nzvals++;
                    break;
                case VTYPE_IVAL:
                    s->nivals++;
                    break;
                case VTYPE_CVAL:
                case VTYPE_UCVAL:
                    s->nvals++;
                    break;
            }
            if (writing) {
                switch (vtype) {
                    case VTYPE_TOMB:
                        kmd_add_tomb(mem, &off, seq);
                        break;
                    case VTYPE_PTOMB:
                        kmd_add_ptomb(mem, &off, seq);
                        break;
                    case VTYPE_ZVAL:
                        kmd_add_zval(mem, &off, seq);
                        break;
                    case VTYPE_IVAL:
                        kmd_add_ival(mem, &off, seq, vdata, vlen);
                        break;
                    case VTYPE_CVAL:
                        kmd_add_cval(mem, &off, seq, vbidx, vboff, vlen, clen);
                        break;
                    case VTYPE_UCVAL:
                        kmd_add_val(mem, &off, seq, vbidx, vboff, vlen);
                        break;
                }
            } else {
                uint64_t       actual_seq;
                enum kmd_vtype actual_vtype;
                uint           actual_vbidx;
                uint           actual_vboff;
                uint           actual_vlen;
                uint           actual_clen;
                const void *   actual_vdata;

                kmd_type_seq(mem, &off, &actual_vtype, &actual_seq);
                assert(vtype == actual_vtype);
                assert(seq == actual_seq);
                switch (vtype) {
                    case VTYPE_UCVAL:
                        kmd_val(mem, &off, &actual_vbidx, &actual_vboff, &actual_vlen);
                        assert(actual_vbidx == vbidx);
                        assert(actual_vboff == vboff);
                        assert(actual_vlen == vlen);
                        break;
                    case VTYPE_CVAL:
                        kmd_cval(mem, &off, &actual_vbidx, &actual_vboff, &actual_vlen, &actual_clen);
                        assert(actual_vbidx == vbidx);
                        assert(actual_vboff == vboff);
                        assert(actual_vlen == vlen);
                        assert(actual_clen == clen);
                        break;
                    case VTYPE_IVAL:
                        kmd_ival(mem, &off, &actual_vdata, &actual_vlen);
                        assert(actual_vlen == vlen);
                        break;
                    case VTYPE_TOMB:
                    case VTYPE_PTOMB:
                    case VTYPE_ZVAL:
                        break;
                }
            }
        }
    }
    if (writing)
        kmd_set_count(mem, &off, 0);

    s->nbytes = off;
}

void
run_kmd_profile(struct kmd_test_profile *tp)
{
    static int headers;
    double ents_per_key;
    double bytes_per_seq;
    double bytes_per_key;
    double tot_ents;
    double tot_tombs;
    double pct_tombs;

    struct kmd_test_stats  read = {}, write = {};
    struct kmd_test_stats *s;

    memset(mem, 0xab, mem_size);

    xrand_init(&tp->xr, seed);
    run_kmd_tp(tp, &write, true);

    xrand_init(&tp->xr, seed);
    run_kmd_tp(tp, &read, true);

    s = &write;
    ents_per_key = 1.0 * s->nseqs / s->nkeys;
    bytes_per_seq = 1.0 * s->nbytes / s->nseqs;
    bytes_per_key = 1.0 * s->nbytes / s->nkeys;

    tot_ents = s->ntombs + s->nptombs + s->nzvals + s->nvals;
    tot_tombs = s->ntombs + s->nptombs + s->nzvals;
    pct_tombs = 100.0 * (tot_tombs / tot_ents);

    if (!headers) {
        headers = 1;

        printf("\n# KMD encoding overhead\n");

        printf(
            "%-5s  %9s  %8s  %10s  %10s\n", "Enc", "%Tombs", "Ents/Key", "Bytes/Key", "Bytes/Ent");
        printf(
            "%-5s  %9s  %8s  %10s  %10s\n", "-----", "------", "--------", "--------", "--------");
    }
    printf(
        "%-5s  %8.0f%%  %8.1f  %10.1f  %10.1f\n",
        test_enc_name(tp->enc),
        pct_tombs,
        ents_per_key,
        bytes_per_key,
        bytes_per_seq);

    if (memcmp(&read, &write, sizeof(read))) {
        printf("ERROR: read stats != write stats\n");
        s = &write;
        printf(
            "write: %lu bytes, %lu keys, %lu seqs, %lu vals, "
            "%lu tombs, %lu ptombs, %lu zvals\n",
            s->nbytes,
            s->nkeys,
            s->nseqs,
            s->nvals,
            s->ntombs,
            s->nptombs,
            s->nzvals);
        s = &read;
        printf(
            "read: %lu bytes, %lu keys, %lu seqs, %lu vals, "
            "%lu tombs, %lu ptombs, %lu zvals\n",
            s->nbytes,
            s->nkeys,
            s->nseqs,
            s->nvals,
            s->ntombs,
            s->nptombs,
            s->nzvals);
    }
}

void
run_kmd_perf(void)
{
    struct kmd_test_stats read = {}, write = {};
    struct timeval        t1, t2, tmp;
    struct xrand          xr;
    double                M = 1024 * 1024;
    double                rtime, wtime;
    uint64_t              i;

    xrand_init(&xr, seed);
    for (i = 0; i < randc; i++)
        randv[i] = xrand64(&xr);

    gettimeofday(&t1, NULL);
    run_kmd_write_perf(&write);
    gettimeofday(&t2, NULL);

    timersub(&t2, &t1, &tmp);
    wtime = tmp.tv_sec + tmp.tv_usec * 1e-6;

    gettimeofday(&t1, NULL);
    run_kmd_read_perf(&read);
    gettimeofday(&t2, NULL);
    timersub(&t2, &t1, &tmp);
    rtime = tmp.tv_sec + tmp.tv_usec * 1e-6;

    printf("\n# KMD encoder performance (values scaled by 1024*1024)\n");

    printf(
        "kmd write %5.0f M keys, %5.0f M ents, %5.0f M bytes"
        ": %5.0f M ents/sec, %5.0f MBytes/sec\n",
        write.nkeys / M,
        write.nseqs / M,
        write.nbytes / M,
        write.nseqs / wtime / M,
        write.nbytes / wtime / M);

    printf(
        "kmd read  %5.0f M keys, %5.0f M ents, %5.0f M bytes"
        ": %5.0f M ents/sec, %5.0f MBytes/sec\n",
        read.nkeys / M,
        read.nseqs / M,
        read.nbytes / M,
        read.nseqs / wtime / M,
        read.nbytes / rtime / M);
}

void
run_kmd_overhead(void)
{
    unsigned      t_epk[] = { 1, 2, 10, 1000 };
    enum test_enc t_enc[] = { enc_short, enc_med, enc_long };
    enum test_mix t_mix[] = { vals_only, mixed, tombs_only };

    int i, j, k;

    for (k = 0; k < NELEM(t_mix); k++) {
        for (i = 0; i < NELEM(t_epk); i++) {
            for (j = 0; j < NELEM(t_enc); j++) {
                struct kmd_test_profile tp = {};

                tp.max_keys = 1000;
                tp.max_ents_per_key = t_epk[i];
                tp.enc = t_enc[j];
                tp.mix = t_mix[k];
                run_kmd_profile(&tp);
            }
        }
    }
}

void
usage(void)
{
    fprintf(stderr, "Usage: [-s seed] [-g] [-o] [-p]\n");
}

int
main(int argc, char *argv[])
{
    int  opt;
    bool general = false;
    bool kmd_overhead = false;
    bool kmd_perf = false;

    seed = time(NULL);

    while ((opt = getopt(argc, argv, "s:goph")) != -1) {
        switch (opt) {
            case 's':
                seed = atoi(optarg);
                break;
            case 'g':
                general = true;
                break;
            case 'o':
                kmd_overhead = true;
                break;
            case 'p':
                kmd_perf = true;
                break;
            case 'h':
            default:
                usage();
                exit(opt == 'h' ? 0 : -1);
        }
    }

    if (optind > argc) {
        usage();
        exit(-1);
    }

    if (!general && !kmd_overhead && !kmd_perf)
        general = kmd_overhead = kmd_perf = true;

    mem = malloc(mem_size);
    randv = malloc(randc * sizeof(*randv));
    if (!mem || !randv)
        return -1;

    printf("seed = %u\n", seed);

    if (general)
        run_encoder_perf(seed);

    if (kmd_overhead)
        run_kmd_overhead();

    if (kmd_perf)
        run_kmd_perf();

    free(mem);
    free(randv);
    return failed ? 1 : 0;
}
