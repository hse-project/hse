/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

/*
 * This example demonstrates how one could add key-value pairs where the value
 * length could be larger than the allowed maximum HSE_KVS_VALUE_LEN_MAX.
 *
 * To put keys, this example uses files passed to it on the commandline. Each
 * file's name forms the prefix of a key and its contents are chunked into the
 * values. For instance, if one were to put /tmp/foo and /tmp/bar into kvs1 in
 * mpool mp1, the commandline would read:
 *
 *            ex5_large_val mp1 kvs1 /tmp/foo /tmp/bar
 *
 * This would put the keys:
 *
 *     /tmp/foo00000000
 *     /tmp/foo00000001
 *     /tmp/foo00000002
 *     ...
 *     /tmp/foo00000NNN
 *
 * for chunks of size HSE_KVS_VALUE_LEN_MAX read from /tmp/foo. Similarly, the file
 * /tmp/bar will be split into multiple chunks starting with keys starting at
 * /tmp/bar00000000
 *
 * To extract the key-value pairs, use the option '-x' on the commandline. For
 * the example above, the commandline will look like this:
 *
 *            ex5_large_val mp1 kvs1 -x /tmp/foo /tmp/bar
 *
 * And the values for each key/file will be output into '/tmp/foo.out' and
 * '/tmp/bar.out' respectively.
 *
 * NOTE - the names of the files given in the extract run must exactly match
 * the file names inserted or the data will not be found.
 */

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/limits.h>

#include <hse/hse.h>

#include "helper.h"

char *progname;

int
extract_kv_to_files(struct hse_kvs *kvs, int file_cnt, char **files)
{
    int                    err = 0, fd, i;
    struct hse_kvs_cursor *cur;
    hse_err_t              rc;

    for (i = 0; i < file_cnt; i++) {
        char        pfx[HSE_KVS_KEY_LEN_MAX];
        char        outfile[NAME_MAX + 8]; /* Extra bytes for '.out' suffix */
        const void *key, *val;
        size_t      klen, vlen;
        bool        eof;
        bool        data_found = false;

        snprintf(outfile, sizeof(outfile), "%s.%s", files[i], "out");
        snprintf(pfx, sizeof(pfx), "%s|", files[i]);
        printf("filename: %s\n", outfile);

        fd = open(outfile, O_RDWR | O_CREAT, 0644);
        if (fd == -1) {
            err = errno;
            fprintf(stderr, "Failed to open %s: %s", outfile, strerror(err));
            return err;
        }

        rc = hse_kvs_cursor_create(kvs, 0, NULL, pfx, strlen(pfx), &cur);
        if (rc) {
            error(rc, "Failed to create cursor");
            err = hse_err_to_errno(rc);
            goto close_file;
        }

        do {
            rc = hse_kvs_cursor_read(cur, 0, &key, &klen, &val, &vlen, &eof);
            if (rc) {
                error(rc, "Failed to read from cursor");
                err = hse_err_to_errno(rc);
                goto cursor_cleanup;
            }
            if (!eof)
                data_found = true;

            if (eof)
                break;

            if (write(fd, val, vlen) != vlen) {
                err = errno;
                goto cursor_cleanup;
            }
        } while (!eof);

      cursor_cleanup:
        rc = hse_kvs_cursor_destroy(cur);
        if (rc) {
            error(rc, "Failed to destroy cursor");
            err = hse_err_to_errno(rc);
        }

      close_file:
        if (close(fd) == -1 && !rc)
            err = errno;

        if (err)
            return err;

        if (!data_found)
            fprintf(stderr, "No chunk keys found for file '%s'\n", files[i]);
    }

    return err;
}

int
put_files_as_kv(struct hse_kvdb *kvdb, struct hse_kvs *kvs, int kv_cnt, char **keys)
{
    int       err = 0, err2, fd, i;
    hse_err_t rc;

    for (i = 0; i < kv_cnt; i++) {
        char    val[HSE_KVS_VALUE_LEN_MAX];
        char    key_chunk[HSE_KVS_KEY_LEN_MAX];
        ssize_t len;
        int     chunk_nr;

        printf("Inserting chunks for %s\n", (char *)keys[i]);
        fd = open(keys[i], O_RDONLY);
        if (fd == -1) {
            err = errno;
            fprintf(stderr, "Error opening file %s: %s\n", keys[i], strerror(err));
            return err;
        }

        chunk_nr = 0;
        do {
            len = read(fd, val, sizeof(val));
            if (len == -1) {
                err = errno;
                fprintf(stderr, "Failed to read %s: %s\n", keys[i], strerror(err));
                break;
            } else if (len == 0) {
                break;
            }

            snprintf(key_chunk, sizeof(key_chunk), "%s|%08x", (char *)keys[i], chunk_nr);

            rc = hse_kvs_put(kvs, 0, NULL, key_chunk, strlen(key_chunk), val, len);
            if (rc) {
                error(rc, "Failed to put data into KVS");
                err = hse_err_to_errno(rc);
                break;
            }

            chunk_nr++;
        } while (!rc && len > 0);

        if (close(fd) == -1) {
            err2 = errno;
            err = err ?: err2;
            fprintf(stderr, "Failed to close %s: %s\n", keys[i], strerror(err2));
        }

        if (err)
            break;
    }

    return err;
}

int
usage()
{
    printf(
        "usage: %s [options] <kvdb> <kvs> <file1> [<fileN> ...]\n"
        "-x  Extract specified files' contents to 'file.out'\n",
        progname);
    return 1;
}

int
main(int argc, char **argv)
{
    char *           kvdb_home, *kvs_name;
    struct hse_kvdb *kvdb;
    struct hse_kvs * kvs;
    int              c;
    bool             extract = false;
    hse_err_t        rc, rc2;
    const char *     paramv[] = { "logging.destination=stdout",
                                  "logging.level=3",
                                  "socket.enabled=false" };
    const size_t     paramc = sizeof(paramv) / sizeof(paramv[0]);

    progname = argv[0];

    while ((c = getopt(argc, argv, "xh")) != -1) {
        switch (c) {
        case 'x':
            extract = true;
            break;
        case 'h':
            usage();
            return 0;
        default:
            break;
        }
    }

    if (argc < 4)
        return usage();

    kvdb_home = argv[optind++];
    kvs_name = argv[optind++];

    rc = hse_init(NULL, paramc, paramv);
    if (rc) {
        error(rc, "Failed to initialize HSE");
        goto out;
    }

    rc = hse_kvdb_open(kvdb_home, 0, NULL, &kvdb);
    if (rc) {
        error(rc, "Failed to open KVDB (%s)", kvdb_home);
        goto hse_cleanup;
    }

    rc = hse_kvdb_kvs_open(kvdb, kvs_name, 0, NULL, &kvs);
    if (rc) {
        error(rc, "Failed to open KVS (%s)", kvs_name);
        goto kvdb_cleanup;
    }

    if (extract) {
        rc = extract_kv_to_files(kvs, argc - optind, &argv[optind]);
    } else {
        rc = put_files_as_kv(kvdb, kvs, argc - optind, &argv[optind]);
    }

    rc2 = hse_kvdb_kvs_close(kvs);
    if (rc2)
        error(rc2, "Failed to close KVS (%s)", kvs_name);
    rc = rc ?: rc2;
  kvdb_cleanup:
    rc2 = hse_kvdb_close(kvdb);
    if (rc2)
        error(rc2, "Failed to close KVDB (%s)", kvdb_home);
    rc = rc ?: rc2;
  hse_cleanup:
    hse_fini();
  out:
    return hse_err_to_errno(rc);
}
