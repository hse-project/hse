/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <stdio.h>

int
pipe_open(FILE **save);

int
pipe_close(FILE **restore, char *find);
