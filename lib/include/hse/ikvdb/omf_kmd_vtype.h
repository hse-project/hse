/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef HSE_KVDB_OMF_KMD_VTYPE_H
#define HSE_KVDB_OMF_KMD_VTYPE_H

/* Each value has a type indicating how it is stored on media.
 * Do not change this enum without considering the impact on backward
 * compatibility.
 */
enum kmd_vtype {
    VTYPE_UCVAL = 0u,  // uncompressed value stored in a vblock
    VTYPE_ZVAL = 1,    // zero-length value (i.e., a key with no value)
    VTYPE_TOMB = 2,    // tombstone
    VTYPE_PTOMB = 3,   // prefix tombstone
    VTYPE_IVAL = 4,    // immediate value, uncompressed, stored in a kblock
    VTYPE_CVAL = 5,    // an LZ4 compressed value stored in a vblock
};

#define NUM_KMD_VTYPES 6

#endif
