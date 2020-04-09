/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2017,2019 Micron Technology, Inc.  All rights reserved.
 */
#include <jni.h>

#ifndef HSE_UTIL_H
#define HSE_UTIL_H

void
throw_eof_exception(JNIEnv *env);

void
throw_gen_exception(JNIEnv *env, const char *msg);

#endif /* HSE_UTIL_H */
