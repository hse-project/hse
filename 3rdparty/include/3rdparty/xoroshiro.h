/* SPDX-License-Identifier: CC0-1.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_XOROSHIRO_H
#define HSE_XOROSHIRO_H

/*
 * Written in 2016 by David Blackman and Sebastiano Vigna (vigna@acm.org)

 * To the extent possible under law, the author has dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide. This software is distributed without any warranty.

 * See <http://creativecommons.org/publicdomain/zero/1.0/>.

 * http://vigna.di.unimi.it/xorshift/xoroshiro128plus.c
 * http://xoroshiro.di.unimi.it/splitmix64.c
 * http://xoroshiro.di.unimi.it/
 */

#include <inttypes.h>

static inline uint64_t
xoroshiro_rotl(const uint64_t x, int k)
{
	return (x << k) | (x >> (64 - k));
}

static inline void
xoroshiro128plus_init(uint64_t *s, uint64_t seed)
{
	uint64_t z;

	z = (seed += UINT64_C(0x9E3779B97F4A7C15));
	z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
	z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
	s[0] = z ^ (z >> 31);

	z = (seed += UINT64_C(0x9E3779B97F4A7C15));
	z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
	z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
	s[1] = z ^ (z >> 31);
}

static inline uint64_t
xoroshiro128plus(uint64_t *s)
{
	const uint64_t s0 = s[0];
	uint64_t s1 = s[1];
	const uint64_t result = s0 + s1;

	s1 ^= s0;
	s[0] = xoroshiro_rotl(s0, 55) ^ s1 ^ (s1 << 14); /* a, b */
	s[1] = xoroshiro_rotl(s1, 36); /* c */

	return result;
}
#endif
