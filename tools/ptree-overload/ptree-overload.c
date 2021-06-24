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
		rc = hse_kvs_put(targ->kvs, 0, key, sizeof(key),
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
		rc = hse_kvs_prefix_delete(targ->kvs, 0, key, sizeof(key),
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
	struct svec         kvdb_oparms = {};
	struct svec         kvs_cparms = {};
	struct svec         kvs_oparms = {};
	const char         *mpool, *kvs;
	char                c;
	int                 rc;

	progname = basename(argv[0]);

	rc = pg_create(&pg, PG_KVDB_OPEN, PG_KVS_OPEN, PG_KVS_CREATE, NULL);
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

	kh_init(mpool, &kvdb_oparms);

	kh_register_kvs(kvs, 0, &kvs_cparms, &kvs_oparms, &dostuff, 0);

	while(!killthreads)
		sleep(1);

	kh_wait();

	kh_fini();

	pg_destroy(pg);

	return 0;
}
