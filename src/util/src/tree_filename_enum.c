/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/inttypes.h>
#include <hse_util/string.h>
#include <hse_util/tree_filename_enum.h>
#include "logging_util.h"

#include "tree_filename_vector.i"

const char *
enum_to_sourcefile(enum hse_src_file_enum index)
{
    if ((int)index < 0 || index >= NELEM(hse_src_file_vec))
        index = 0;

    return hse_src_file_vec[index];
}

#include "tree_filename_hash.i"

enum hse_src_file_enum
sourcefile_to_enum(const char *sourcefile)
{
    const char *       end, *prev, *comp, *file;
    char               buf[128];
    struct file_match *p;

    end = prev = comp = file = sourcefile;

    /* Scan sourcefile in an attempt to point file at the last component
     * of the path, comp at the second to last component of the path,
     * and prev at the third to last component of the path.
     */
    while (*end) {
        if (*end++ == '/') {
            prev = comp;
            comp = file;
            file = end;
        }
    }

    /* If "/kbuild." was found in the second to last component of the path,
     * then effectively eliminate it by concatenating the prev and file
     * components and using the result as the file name to look up.
     *
     * For example:
     *
     * if:
     *   sourcefile = "/a/b/c/kbuild.foo/file.c"
     *   prev = "c/kbuild.foo/file.c"
     *   comp = "kbuild.foo/file.c"
     *   file = "file.c"
     *
     * then:
     *   comp = "c/file.c";
     */
    if (*comp == 'k' && 0 == strncmp("kbuild.", comp, 7)) {
        size_t complen = comp - prev;

        if (end - prev - complen < sizeof(buf)) {
            comp = strncpy(buf, prev, complen);
            end = strcpy(buf + complen, file) + (end - file);
        }
    }

    p = hse_lookup_filename(comp, end - comp);
    if (!p) {
        static const char *last;
        char               msg[192];

        if (sourcefile != last) {
            last = sourcefile;

            snprintf(
                msg,
                sizeof(msg),
                "%s: hse_lookup_filename failed for %s:%s\n",
                __func__,
                sourcefile,
                comp);
            backstop_log(msg);
        }

        return HSE_FEI_UNKNOWN_FILE;
    }

    return p->fm_index;
}
