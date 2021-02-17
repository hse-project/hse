/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_CPARAMS_H
#define HSE_KVDB_CPARAMS_H

#include <sys/types.h>
#include <stddef.h>

/*
 * Steps to add a new kvdb create parameter:
 * 1. Add a new struct element to struct kvdb_cparams.
 * 2. Add a new entry to kvdb_cparams_table[].
 * 3. Add a new initial value to the struct in kvdb_cparams_defaults()
 * 4. Update kvdb_uu_interface.c to properly handle parameter during
 *    kvdb_create()
 * 5. Update kvdb_cparams_validate() as needed.
 */

/**
 * struct kvdb_cparams - parameters for kvdb creation
 * uid, gid, mode will be moved to kvdb_cparams
 * @dur_capacity: durability capacity in MiB
 */
struct kvdb_cparams {
    size_t        dur_capacity;
    u8            filecnt;
    char          capdir[PATH_MAX];
    char          stgdir[PATH_MAX];
    unsigned long cpmagic;
};

void
kvdb_cparams_table_reset(void);

struct param_inst *
kvdb_cparams_table(void);

/**
 * kvdb_cparams_help() -
 * @buf: Buffer to be filled with the help message
 * @buf_sz: Size of buf
 * @cparams: Default values for more informative help.  If NULL,
 *           system defaults are used.
 *
 * Fills buf with a help string
 *
 * Return: a pointer to the buffer buf
 */
char *
kvdb_cparams_help(char *buf, size_t buf_sz, struct kvdb_cparams *cparams);

/**
 * kvdb_cparams_validate() - validate parameters
 * @cparams: create time parameters to be validated
 */
int
kvdb_cparams_validate(struct kvdb_cparams *cparams);

/**
 * kvdb_cparams_print() - prints parameter value to the log
 * @cparams: parameters to print
 */
void
kvdb_cparams_print(struct kvdb_cparams *cparams);

/**
 * kvdb_cparams_defaults() - get default parameter values
 */
struct kvdb_cparams
kvdb_cparams_defaults(void);

int
kvdb_cparams_parse(
    int                  argc,
    char **              argv,
    struct kvdb_cparams *params,
    int *                next_arg,
    unsigned int         flag);

void
kvdb_cparams_free(struct kvdb_cparams *cparams);

/**
 * kvdb_cparams_diff() - invokes callback for non-default values
 * @cp: cparams to compare against
 * @arg: optional callback argument
 * @callback: invoked as callback(key, value, arg) for non-default values
 */
void
kvdb_cparams_diff(
    struct kvdb_cparams *cp,
    void *               arg,
    void (*callback)(const char *, const char *, void *));

#endif /* HSE_KVDB_CPARAMS_H */
