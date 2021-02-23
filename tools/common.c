/*
 * Copyright (C) 2015-2017,2019 Micron Technology, Inc.  All rights reserved.
 */

/*
 * common functions for kvs tools
 */

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <hse/hse_limits.h>

#include <hse_util/fmt.h>

#include <tools/common.h>

struct app_opts Opts;

static void
error(int err, char *fmt, va_list ap)
{
    vfprintf(stderr, fmt, ap);
    if (Opts.lineno)
        fprintf(stderr, ": %d", Opts.lineno);
    if (err)
        fprintf(stderr, ": %s\n", strerror(err));
    else
        fprintf(stderr, "\n");
}

int
warn(int err, char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    error(err, fmt, ap);
    va_end(ap);

    return 1;
}

void
fatal(int err, char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    error(err, fmt, ap);
    va_end(ap);

    assert(0);
    exit(1);
}

void
rp_usage(void)
{
    exit(1);
}

static inline unsigned int
atobin(char c)
{
    static const char hex[] = "0123456789abcdef";
    const char *      dp = __builtin_strchr(hex, c | 32); /* gcc4.4 bug 36513 */

    return dp ? dp - hex : -1;
}

int
fmt_data(char *out, char *in)
{
    /*
	 * If str begins with "0x", convert to binary:
	 * format is BE, bytes in order: 0x010203 results in 010203
	 * NB: this does not need to be a proper int:
	 * the str 0xc creates a single byte 0x0c;
	 * but longer partial keys implicitly add a trailing zero:
	 * the str 0x012 creates a two byte buffer 0120.
	 *
	 * Allows embedded spaces, dashes, colons for readability:
	 *	"0x00010203-04050607:08090a0b 0c0d0e0f"
	 * which parses as 16 bytes from 00-0f.
	 */

    unsigned char *buf = (void *)out;
    int            len;

    if (!in)
        return 0;

    len = strlen(in);
    if (len >= 2 && in[0] == '0' && in[1] == 'x') {
        in += 2;
        for (len = 0; *in; ++len) {
            if (*in == '-' || *in == ':' || *in == ' ')
                ++in;
            buf[len] = atobin(*in++) << 4;
            if (*in)
                buf[len] |= atobin(*in++);
            else if (len == 1)
                buf[len] >>= 4;
        }
    } else {
        strcpy(out, in);
        if (Opts.zero)
            ++len;
    }

    return len;
}

void
show(const void *key, size_t klen, const void *val, size_t vlen, int showlen)
{
    static char kbuf[HSE_KVS_KLEN_MAX * 3];
    static char vbuf[HSE_KVS_VLEN_MAX * 3];
    size_t      koff, voff;

    kbuf[0] = vbuf[0] = '\000';
    koff = voff = 0;

    if (showlen) {
        koff = sprintf(kbuf, "%-3lu ", klen);
        voff = sprintf(vbuf, "%-4lu ", vlen);
    }

    if (Opts.kmax > 0)
        fmt_pe(kbuf + koff, Opts.kmax + 1, key, klen);

    if (Opts.vmax > 0)
        fmt_pe(vbuf + voff, Opts.vmax + 1, val, vlen);

    if (Opts.kmax > 0 || showlen)
        fputs(kbuf, stdout);

    if (Opts.vmax > 0 || showlen) {
        fputs(" = ", stdout);
        fputs(vbuf, stdout);
    }

    fputc('\n', stdout);
}

void
show_hex(const void *key, size_t klen, const void *val, size_t vlen, int showlen)
{
    static char kbuf[HSE_KVS_KLEN_MAX * 2 + 8];
    static char vbuf[HSE_KVS_VLEN_MAX * 2 + 8];
    size_t      koff, voff;

    kbuf[0] = vbuf[0] = '\000';
    koff = voff = 0;

    if (showlen) {
        koff = sprintf(kbuf, "%-3lu ", klen);
        voff = sprintf(vbuf, "%-4lu ", vlen);
    }

    if (Opts.kmax > 0)
        fmt_hexp(kbuf + koff, Opts.kmax * 2 + 1, key, klen, NULL, 0, NULL, NULL);

    if (Opts.kmax > 0)
        fmt_hexp(vbuf + voff, Opts.vmax * 2 + 1, val, vlen, NULL, 0, NULL, NULL);

    if (Opts.kmax > 0 || showlen)
        fputs(kbuf, stdout);

    if (Opts.vmax > 0 || showlen) {
        fputs(" = ", stdout);
        fputs(vbuf, stdout);
    }

    fputc('\n', stdout);
}
