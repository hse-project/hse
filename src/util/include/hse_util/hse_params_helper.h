/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PARAMS_HELPER_H
#define HSE_PARAMS_HELPER_H

struct hse_params;

/**
 * hse_parse_cli() - parse params from the command line
 * @argc:     argument count
 * @argv:     argument list
 * @next_arg: pointer to last unparsed argument
 * @flag:     enable advanced parameters
 * @params:   configuration parameters
 */
uint64_t
hse_parse_cli(int argc, char **argv, int *next_arg, int flag, struct hse_params *params);

/**
 * hse_get_param_table() - return underlying params table
 * @table:  pointer to param_inst
 * @target: requested table
 */
void
hse_get_param_table(void **table, char *target);

/**
 * hse_generate_help() - generate help message
 * @buf:      target buffer
 * @buf_sz:   size of target buffer
 * @target:   requested table
 */
char *
hse_generate_help(char *buf, size_t buf_sz, char *target);

#endif /* HSE_PARAMS_HELPER_H */
