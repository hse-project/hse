/*
 * Copyright (C) 2015-2017 Micron Technology, Inc. All rights reserved.
 */
#ifndef HSE_TOOLS_PARM_GROUPS
#define HSE_TOOLS_PARM_GROUPS

/* "parm_groups" and "svecs" are used by hse tools for parsing
 * HSE config parameters from command line options and passing them to
 * hse_kvdb_open, hse_kvs_open, etc.
 */

#include <stddef.h>

struct parm_groups;

/* Max group name length */
#define PG_NAME_MAX 64

#define LIST_SEP_CHAR  '|'
#define LIST_SEP_STR   "|"

/* These are suggested group names.  Clients are free to use other
 * names or define additional groups as they see fit.
 */
#define PG_HSE_GLOBAL  "hse-gparams"  LIST_SEP_STR "hse-gparms"  LIST_SEP_STR "gp"
#define PG_KVDB_CREATE "kvdb-cparams" LIST_SEP_STR "kvdb-cparms" LIST_SEP_STR "dcp"
#define PG_KVDB_OPEN   "kvdb-oparams" LIST_SEP_STR "kvdb-oparms" LIST_SEP_STR "dop"
#define PG_KVS_CREATE  "kvs-cparams"  LIST_SEP_STR "kvs-cparms"  LIST_SEP_STR "kcp"
#define PG_KVS_OPEN    "kvs-oparams"  LIST_SEP_STR "kvs-oparms"  LIST_SEP_STR "kop"

struct svec {
    const char **strv;
    size_t       strc;
    size_t       strc_max;
};

void
svec_init(struct svec *sv);

void
svec_reset(struct svec *sv);

int
svec_append_pg(struct svec *sv, struct parm_groups *pg, ...);

int
svec_append(struct svec *sv, ...);

int
svec_append_svec(struct svec *sv, ...);

int
pg_create(struct parm_groups **pg, ...);

void
pg_destroy(struct parm_groups *pg);

int
pg_define_group(struct parm_groups *pg, const char *group_name);

int
pg_set_parms(struct parm_groups *self, const char *group_name, ...);

/*
 * Parse argv list starting at optind, save results in parm_groups object.
 *
 * @param argc: Number of strings in argv
 * @param argv: Array of strings
 * @param[in/out] optind: like getopt's optind
 *
 * Return value:
 *   ENOMEM -- Out of memory.
 *   EINVAL -- Param was found without a group.
 *   0      -- Success.
 *
 * Upon return with rc == 0:
 *   - If *optind <  argc, then processing stopped at argv[*optind].
 *   - If *optind == argc, then argv was processed to the end.
 *   - If *optind >  argc, then caller passed *optind that was out of range.
 *
 * Upon return with rc != 0:
 *   - Assert *optind < argc.
 *   - Processing stopped at argv[*optind].
 *
 * See example at top of file.
 */
int
pg_parse_argv(struct parm_groups *pg, int argc, char **argv, int *optind);

#endif
