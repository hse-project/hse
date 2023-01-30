/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KEY_GENERATOR_H
#define HSE_KEY_GENERATOR_H

#include <stdint.h>

struct key_generator;

struct key_generator *
create_key_generator(uint64_t key_space_size, int32_t key_width);

void
destroy_key_generator(struct key_generator *kg);

void
get_key(struct key_generator *self, uint8_t *key_buffer, uint64_t key_index);

#endif
