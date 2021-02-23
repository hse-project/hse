/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2017 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CORE_HSE_TEST_RANDOM_BUFFER_H
#define HSE_CORE_HSE_TEST_RANDOM_BUFFER_H

#include <hse_util/inttypes.h>

/* randomize_buffer
 *
 * Write pseudo-random data to a buffer, based on a specified seed
 */
void
randomize_buffer(void *buf, size_t len, unsigned int seed);

/*
 * validate_random_buffer
 *
 * Take advantage of the fact that starting with the same seed will generate
 * the same pseudo-random data, for an easy way to validate a buffer
 */
int
validate_random_buffer(void *buf, size_t len, unsigned int seed);

/* generate_random_u32
 *
 * Create and return a random u32 between min and max inclusive with
 * a uniform distribution.
 */
u32
generate_random_u32(u32 min, u32 max);

/* permute_u32_sequence
 *
 * Given an array of u32 values, randomly permute its elements without
 * introducing repeats.
 */
void
permute_u32_sequence(u32 *values, u32 num_values);

/* generate_random_u32_sequence
 *
 * Fill out an array of uniformly distributed random u32 values between min
 * and max inclusive.
 */
void
generate_random_u32_sequence(u32 min_value, u32 max_value, u32 *values, u32 num_values);

#endif
