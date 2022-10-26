/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2017 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KEY_GENERATOR_H
#define HSE_KEY_GENERATOR_H

#include <hse/util/inttypes.h>

struct key_generator;

struct key_generator *
create_key_generator(u64 key_space_size, s32 key_width);

void
destroy_key_generator(struct key_generator *kg);

void
get_key(struct key_generator *self, u8 *key_buffer, u64 key_index);

#endif
