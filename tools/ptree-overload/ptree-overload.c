/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc. All rights reserved.
 */
#include <endian.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <hse/hse.h>

#include <cli/param.h>

#include "kvs_helper.h"

char *progname;
int killthreads = 0;

struct _opts {
	unsigned long nkeys;
	unsigned long nptombs;
} opts = {
	.nkeys = 130000,
	.nptombs = 60000,
};

void
dostuff(void *arg)
{
	struct thread_arg *targ = arg;
	uint64_t i;
	char key[sizeof(uint64_t)];

	/* Insert keys */
	for (i = 0; i < opts.nkeys; i++) {
		int rc;
		uint64_t *k = (uint64_t *)key;

		*k = htole64(i);
		rc = hse_kvs_put(targ->kvs, 0, NULL, key, sizeof(key),
			     key, sizeof(key));
		if (rc) {
			killthreads = 1;
			fprintf(stderr, "Failed to put key: %d\n", rc);
		}
	}

	/* Insert ptombs */
	for (i = 0; i < opts.nptombs; i++) {
		int rc;
		size_t kvs_plen;

		snprintf(key, sizeof(key), "k%06lu", i);
		rc = hse_kvs_prefix_delete(targ->kvs, 0, NULL, key, sizeof(key),
				       &kvs_plen);
		if (rc) {
			killthreads = 1;
			fprintf(stderr, "Failed to pdel key: %d\n", rc);
		}
	}

	killthreads = 1;
}

void
syntax(const char *fmt, ...)
{
	char    msg[256];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	fprintf(stderr, "%s: %s, use -h for help\n", progname, msg);
}

void
usage(void)
{
	printf(
		"usage: %s [options] kvdb kvs [param=value ...]\n"
		"-k nkeys   Number of keys\n"
		"-p nptombs Number of ptombs\n"
		"-Z config  Path to global config file\n"
		"-h      Print this help menu\n"
		, progname);

	printf("\nDescription:\n");
	printf("Insert keys and ptombs\n");
	printf("\n");
	exit(0);
}

int
main(int argc, char **argv)
{
	struct parm_groups *pg = NULL;
	struct svec         hse_gparms = { 0 };
	struct svec         kvdb_oparms = { 0 };
	struct svec         kvs_cparms = { 0 };
	struct svec         kvs_oparms = { 0 };
	const char         *mpool, *kvs, *config = NULL;
	char                c;
	int                 rc;

	progname = basename(argv[0]);

	rc = pg_create(&pg, PG_HSE_GLOBAL, PG_KVDB_OPEN, PG_KVS_OPEN, PG_KVS_CREATE, NULL);
	if (rc)
		fatal(rc, "pg_create");

	while ((c = getopt(argc, argv, ":k:p:")) != -1) {
		char *errmsg, *end;

		errmsg = end = 0;
		errno = 0;
		switch (c) {
		case 'h':
			usage();
			exit(0);
		case 'k':
			opts.nkeys = strtoul(optarg, &end, 0);
			errmsg = "invalid nkeys";
			break;
		case 'p':
			opts.nptombs = strtoul(optarg, &end, 0);
			errmsg = "invalid nptombs";
			break;
		case 'Z':
			config = optarg;
			break;
		case '?':
			syntax("invalid option -%c", optopt);
			exit(EX_USAGE);
		case ':':
			syntax("option -%c requires a parameter", optopt);
			exit(EX_USAGE);
		default:
			fprintf(stderr, "option -%c ignored\n", c);
			break;
		}

		if (errno && errmsg) {
			syntax("%s", errmsg);
			exit(EX_USAGE);
		} else if (end && *end) {
			syntax("%s '%s'", errmsg, optarg);
			exit(EX_USAGE);
		}
	}

	if (argc - optind < 2) {
		syntax("missing required parameters");
		exit(EX_USAGE);
	}

	mpool = argv[optind++];
	kvs   = argv[optind++];

	rc = pg_parse_argv(pg, argc, argv, &optind);
	switch (rc) {
	case 0:
		if (optind < argc)
			fatal(0, "unknown parameter: %s", argv[optind]);
		break;
	case EINVAL:
		fatal(0, "missing group name (e.g. %s) before parameter %s\n",
			PG_KVDB_OPEN, argv[optind]);
		break;
	default:
		fatal(rc, "error processing parameter %s\n", argv[optind]);
		break;
	}

	rc = rc ?: svec_append_pg(&hse_gparms, pg, PG_HSE_GLOBAL, NULL);
	rc = rc ?: svec_append_pg(&kvdb_oparms, pg, PG_KVDB_OPEN, NULL);
	rc = rc ?: svec_append_pg(&kvs_cparms, pg, PG_KVS_CREATE, NULL);
	rc = rc ?: svec_append_pg(&kvs_oparms, pg, PG_KVS_OPEN, NULL);
	if (rc)
		fatal(rc, "failed to parse params\n");

	kh_init(config, mpool, &hse_gparms, &kvdb_oparms);

	kh_register_kvs(kvs, 0, &kvs_cparms, &kvs_oparms, &dostuff, 0);

	while(!killthreads)
		sleep(1);

	kh_wait();

	kh_fini();

	pg_destroy(pg);
	svec_reset(&hse_gparms);
	svec_reset(&kvdb_oparms);
	svec_reset(&kvs_cparms);
	svec_reset(&kvs_oparms);

	return 0;
}
