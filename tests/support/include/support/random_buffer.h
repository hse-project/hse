/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2017,2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef SUPPORT_RANDOM_BUFFER_H
#define SUPPORT_RANDOM_BUFFER_H

#include <stddef.h>
#include <stdint.h>

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
uint32_t
generate_random_u32(uint32_t min, uint32_t max);

/* permute_u32_sequence
 *
 * Given an array of u32 values, randomly permute its elements without
 * introducing repeats.
 */
void
permute_u32_sequence(uint32_t *values, uint32_t num_values);

/* generate_random_u32_sequence
 *
 * Fill out an array of uniformly distributed random u32 values between min
 * and max inclusive.
 */
void
generate_random_u32_sequence(
    uint32_t  min_value,
    uint32_t  max_value,
    uint32_t *values,
    uint32_t  num_values);

/* generate_random_u32_sequence_unique
 *
 * Same as generate_random_u32_sequence(), but all values are unique.
 */
void
generate_random_u32_sequence_unique(
    uint32_t  min_value,
    uint32_t  max_value,
    uint32_t *values,
    uint32_t  num_values);

#endif
