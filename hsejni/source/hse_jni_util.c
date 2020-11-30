/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2017,2019 Micron Technology, Inc.  All rights reserved.
 */
#include <jni.h>
#include <hse_jni_util.h>

void
throw_no_class_def_found_error(JNIEnv *env, const char *classname)
{
    jclass cls = (*env)->FindClass(env, "java/lang/NoClassDefFoundError");

    (*env)->ThrowNew(env, cls, classname);
}

void throw(JNIEnv * env, const char *classname, const char *msg)
{
    jclass cls = (*env)->FindClass(env, classname);

    if (cls == NULL)
        throw_no_class_def_found_error(env, classname);
    else
        (*env)->ThrowNew(env, cls, msg);
}

void
throw_eof_exception(JNIEnv *env)
{
    throw(env, "org/micron/hse/HSEEOFException", NULL);
}

void
throw_gen_exception(JNIEnv *env, const char *msg)
{
    throw(env, "org/micron/hse/HSEGenException", msg);
}
