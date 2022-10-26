/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#include <hse/types.h>

const char *
err_ctx_strerror(const int ctx)
{
    switch ((enum hse_err_ctx)ctx) {
    case HSE_ERR_CTX_NONE:
        return "No context";
    case HSE_ERR_CTX_TXN_EXPIRED:
        return "Transaction expired";
    }

    return "Undefined";
}
