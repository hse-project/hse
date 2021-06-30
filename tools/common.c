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

#include <hse/hse.h>

#include <hse_util/fmt.h>
#include <hse_util/minmax.h>

#include <tools/common.h>

struct app_opts Opts;

static void
error(hse_err_t err, char *fmt, va_list ap)
{
    char user_msg[128];
    char err_msg[128];
    bool user_msg_empty, need_newline;
    size_t off, n;

    off = 0;

    n = vsnprintf(user_msg, sizeof(user_msg), fmt, ap);

    if (err) {
        hse_err_to_string(err, err_msg + off, sizeof(err_msg) - off, &n);
        off = min(off + n, sizeof(err_msg) - 1);

        n = snprintf(err_msg + off, sizeof(err_msg) - off, " (0x%lx)", err);
        off = min(off + n, sizeof(err_msg) - 1);
    }

    user_msg_empty = user_msg[0] == '\0';
    need_newline = off > 0 && err_msg[off-1] != '\n';

    fprintf(stderr, "%s%s%s%s", user_msg,
        user_msg_empty ? "" : " ",
        err_msg, need_newline ? "\n" : "");
}


void
warn(hse_err_t err, char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    error(err, fmt, ap);
    va_end(ap);
}

void
fatal(hse_err_t err, char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    error(err, fmt, ap);
    va_end(ap);

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
    static char kbuf[HSE_KVS_KEY_LEN_MAX * 3];
    static char vbuf[HSE_KVS_VALUE_LEN_MAX * 3];
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
    static char kbuf[HSE_KVS_KEY_LEN_MAX * 2 + 8];
    static char vbuf[HSE_KVS_VALUE_LEN_MAX * 2 + 8];
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
