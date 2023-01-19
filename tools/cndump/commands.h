/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef CNDUMP_COMMANDS_H
#define CNDUMP_COMMANDS_H

#define CNDB_COMMAND_NAME "cndb"
#define CNDB_COMMAND_DESC "dump a KVDB's CNDB log"

#define KVSET_COMMAND_NAME "kvset"
#define KVSET_COMMAND_DESC "dump a kvset"

#define MBLOCK_COMMAND_NAME "mblock"
#define MBLOCK_COMMAND_DESC "dump an mblock (hblock, kblock or vblock)"

void
cndb_cmd(int argc, char **argv);
void
kvset_cmd(int argc, char **argv);
void
mblock_cmd(int argc, char **argv);

#endif
