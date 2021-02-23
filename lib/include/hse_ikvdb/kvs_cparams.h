/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_CPARAMS_H
#define HSE_KVS_CPARAMS_H

/*
 * Steps to add a new kvs create parameter:
 * 1. Add a new struct element to struct kvs_cparams.
 * 2. Add a new entry to kvs_cparams_table[].
 * 3. Add a new initial value to the struct in kvs_cparams_defaults()
 * 4. Update kvs_uu_interface.c to properly handle parameter during kvs_create()
 * 5. Update kvs_cparams_validate() as needed.
 */

struct kvdb_cparams;

/* See struct kvs_cp_table in kvs_cparams.c for field descriptions. */
struct kvs_cparams {
    unsigned int  cp_fanout;
    unsigned int  cp_pfx_len;
    unsigned int  cp_pfx_pivot;
    unsigned int  cp_kvs_ext01;
    unsigned int  cp_sfx_len;
    unsigned long cp_cpmagic;
};

void
kvs_cparams_table_reset(void);

struct param_inst *
kvs_cparams_table(void);

/**
 * kvs_cparams_help() -
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
kvs_cparams_help(char *buf, size_t buf_sz, struct kvs_cparams *cparams);

/**
 * kvs_cparams_validate() - validate parameters
 * @cparams: create time parameters to be validated
 */
int
kvs_cparams_validate(struct kvs_cparams *cparams);

/**
 * kvs_cparams_print() - prints parameter value to the log
 * @cparams: parameters to print
 */
void
kvs_cparams_print(struct kvs_cparams *cparams);

/**
 * kvs_cparams_defaults() - get default parameter values
 */
struct kvs_cparams
kvs_cparams_defaults(void);

int
kvs_cparams_parse(int argc, char **argv, struct kvs_cparams *params, int *next_arg);

/**
 * kvs_cparams_diff() - invokes callback for non-default values
 * @cp: cparams to compare against
 * @arg: optional callback argument
 * @callback: invoked as callback(key, value, arg) for non-default values
 */
void
kvs_cparams_diff(
    struct kvs_cparams *cp,
    void *              arg,
    void (*callback)(const char *, const char *, void *));

#endif /* HSE_KVS_CPARAMS_H */
