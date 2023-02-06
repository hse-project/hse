<!--
SPDX-License-Identifier: Apache-2.0 OR MIT

SPDX-FileCopyrightText: Copyright 2020 Micron Technology, Inc.
-->

# Overview

This document describes how to use clang-format (version 3.9.1 or
higher) to reformat a single file within the hse repository.

## Preconditions:

(1) Your current working directory is "hse" (i.e., the root of
    the tree).

(2) The file to be reformatted in place is:

        src/cn/cn_tree.c


## Reformatting the file in place:

Issue the following command:

        clang-format -style=file -i -fallback-style=none src/cn/cn_tree.c
