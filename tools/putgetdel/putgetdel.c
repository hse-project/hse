/*
 * Copyright (C) 2015 Micron Technology, Inc.  All rights reserved.
 */

#include <assert.h>
#include <getopt.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sysexits.h>
#include <sys/resource.h>
#include <sys/time.h>

#include <hse/hse.h>
#include <hse/hse_version.h>

#include <hse_util/compiler.h>
#include <hse_util/hse_params_helper.h>
#include <hse_util/inttypes.h>
#include <tools/key_generation.h>
#include <hse_util/parse_num.h>

/* Default key/value lengths */
#define KLEN_DEFAULT   23
#define VLEN_DEFAULT   1018

#define KLEN_MAX  1000
#define VLEN_MAX  (10*1024)


struct opts {
	bool    help;
	bool    version;
	char   *mpool;
	char   *kvs;
	u64     keys;
	uint    klen;
	uint    vlen;
	uint    threads;
	bool    sync;
	bool    ckvs;
	bool    ckvdb;
	bool    unclean;
	bool    show_ops;
	bool    dryrun;
	bool    do_all;
	bool    do_put;
	bool    do_vput;
	bool    do_up;
	bool    do_vup;
	bool    do_del;
	bool    do_vdel;
	bool    do_pdel;
	bool    binary;
	u64     kstart;
	u32     errcnt;
	bool    params;
};


#define KEY_SHOWLEN  23
#define VAL_SHOWLEN  35

char *KEY_PREFIX = "K%016lx";
char *VAL_PREFIX = "V%016lx_%016u";

struct opts opt;

const char *mode = "";
const char *progname = NULL;
struct timeval tv_start;
int verbose = 0;
u32 errors = 0;

static struct key_generator *key_gen;
static const long key_space_size = 4000000000UL;

struct hse_params *params;

pthread_barrier_t   barrier;
struct hse_kvdb *kvdb;

struct thread_info {
	struct hse_kvs *kvs;
	pthread_t       tid;
	uint            id;

	char       *kvs_name;
	bool        joined;

	/* reference key */
	void       *ref_key;
	size_t      ref_klen;

	/* reference value */
	void       *ref_val;
	size_t      ref_vlen;

	/* buffer for kvdb_get */
	void       *get_val;

	void       *pfx;
	int         pfxlen;
};

static void syntax(const char *fmt, ...);
static void quit(const char *fmt, ...);
static void usage(void);
static void rparam_usage(void);

/*
 * Use our own asserts so they're enabled in all builds.
 * This code relies on them to catch errors.
 */
#define my_assert(condition) \
	do { \
		int ass_hurts = !(condition); \
		if (ass_hurts) { \
			fprintf(stderr,\
				"assert(%s) failed at %s:%d\n", #condition, \
				__FILE__, __LINE__); \
			exit(-1); \
		} \
	} while (0)

static void
quit(const char *fmt, ...)
{
	char msg[256];
	va_list ap;

	if (fmt && *fmt) {
		va_start(ap, fmt);
		vsnprintf(msg, sizeof(msg), fmt, ap);
		va_end(ap);
		fprintf(stderr, "%s: %s\n", progname, msg);
		fflush(stderr);
	}
	exit(-1);
}

static void
syntax(const char *fmt, ...)
{
	char msg[256];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	fprintf(stderr, "%s: %s\nUse -h for help.\n", progname, msg);
	exit(EX_USAGE);
}

#define merr_quit(detail, err)			\
	quit("%s:%d: %s: %ld",			\
		__FILE__, __LINE__,		\
		(detail), (err));

void
announce_header(void)
{
	if (!verbose)
		return;

	printf("*** %8s %7s %7s %7s %8s  %s\n",
		"TID", "USER", "SYS", "REAL", "MODE", "MESSAGE");
}

void
announce(const char *msg)
{
	struct timeval tv_now;
	struct rusage rusage;
	int rc;

	if (!verbose)
		return;

	gettimeofday(&tv_now, NULL);

	rc = getrusage(RUSAGE_SELF, &rusage);
	if (rc == 0) {
		long utime, stime, rtime;

		rtime = (tv_now.tv_sec - tv_start.tv_sec) * 1000000;
		rtime += (tv_now.tv_usec - tv_start.tv_usec);
		utime = rusage.ru_utime.tv_sec * 1000000
			+ rusage.ru_utime.tv_usec;
		stime = rusage.ru_stime.tv_sec * 1000000
			+ rusage.ru_stime.tv_usec;

		printf("*** %8lx %7ld %7ld %7ld %8s  %s\n",
			pthread_self() & 0xffffffffu,
			utime / 1000, stime / 1000, rtime / 1000,
			mode, msg);
	}
}

/*----------------------------------------------------------------
 * Command Line Processing
 */

enum opt_enum {
	opt_binary	= 'b',
	opt_keys	= 'c',
	opt_help	= 'h',
	opt_klen        = 'l',
	opt_vlen        = 'L',
	opt_dryrun	= 'n',

	opt_do_put	= 'p',
	opt_do_vput	= 'P',

	opt_do_up	= 'u',
	opt_do_vup	= 'U',

	opt_do_del	= 'd',
	opt_do_vdel	= 'D',

	opt_version	= 'V',
	opt_verbose	= 'v',
	opt_kstart      = 's',
	opt_errcnt      = 'e',
	opt_params      = 'C',
	opt_threads     = 't',

	opt_sync	= 1024,
	opt_ckvs,
	opt_ckvdb,
	opt_unclean,
	opt_do_pdel,
};


struct option longopts[] = {
	{ "binary",     no_argument,        NULL,  opt_binary },
	{ "sync",       no_argument,        NULL,  opt_sync },
	{ "ckvs",       no_argument,        NULL,  opt_ckvs },
	{ "ckvdb",      no_argument,        NULL,  opt_ckvdb },
	{ "unclean",    no_argument,        NULL,  opt_unclean },
	{ "dryrun",     no_argument,        NULL,  opt_dryrun },
	{ "help",       no_argument,        NULL,  opt_help },
	{ "keys",       required_argument,  NULL,  opt_keys },
	{ "klen",       required_argument,  NULL,  opt_klen },
	{ "vlen",       required_argument,  NULL,  opt_vlen },
	{ "threads",    required_argument,  NULL,  opt_threads },

	{ "put",        no_argument,        NULL,  opt_do_put },
	{ "vput",       no_argument,        NULL,  opt_do_vput },
	{ "up",         no_argument,        NULL,  opt_do_up },
	{ "vup",        no_argument,        NULL,  opt_do_vup },
	{ "del",        no_argument,        NULL,  opt_do_del },
	{ "vdel",       no_argument,        NULL,  opt_do_vdel },
	{ "pdel",       no_argument,        NULL,  opt_do_pdel },


	{ "verbose",    optional_argument,  NULL,  opt_verbose },
	{ "version",    no_argument,        NULL,  opt_version  },
	{ "kstart",     required_argument,  NULL,  opt_kstart  },
	{ "errcnt",     required_argument,  NULL,  opt_errcnt  },
	{ "params",     no_argument,        NULL,  opt_params  },

	{ 0, 0, 0, 0 }
};

/* A thread-safe version of strerror().
 */
char *
strerror(int errnum)
{
    static thread_local char tls_errbuf[128];

    if (!strerror_r(errnum, tls_errbuf, sizeof(tls_errbuf)))
        snprintf(tls_errbuf, sizeof(tls_errbuf), "error %d", errnum);

    return tls_errbuf;
}


static
void
options_default(
	struct opts *opt)
{
	memset(opt, 0, sizeof(*opt));
	opt->keys = 10;
	opt->threads = 1;
	opt->do_all = true;
	opt->errcnt = 1;
	opt->klen = KLEN_DEFAULT;
	opt->vlen = VLEN_DEFAULT;
}

#define GET_VALUE(TYPE, OPTARG, VALUE)					\
do {									\
	if (parse_##TYPE(OPTARG, VALUE)) {				\
		syntax("Unable to parse "#TYPE" number: '%s'", OPTARG);	\
	}								\
} while (0)

#define GET_DOUBLE(OPTARG, VALUE)					\
do {									\
	if (1 != sscanf(OPTARG, "%lg", VALUE)) {			\
		syntax("Unable to parse double: '%s'", OPTARG);		\
	}								\
} while (0)

void
options_parse(
	int argc,
	char **argv,
	struct opts *opt,
	int *last_arg)
{
	int done;

	/* Dynamically build optstring from longopts[] for getopt_long_only().
	 */
	const size_t optstringsz =
		(sizeof(longopts) / sizeof(longopts[0])) * 3 + 3;
	char optstring[optstringsz + 1];
	const struct option *longopt;
	char *pc = optstring;

	*pc++ = ':';    /* Disable getopt error messages */

	for (longopt = longopts; longopt->name; ++longopt) {
		if (!longopt->flag && isprint(longopt->val)) {
			*pc++ = longopt->val;
			if (longopt->has_arg == required_argument) {
				*pc++ = ':';
			} else if (longopt->has_arg == optional_argument) {
				*pc++ = ':';
				*pc++ = ':';
			}
		}
	}
	*pc = '\000';

	done = 0;
	while (!done) {
		int curind = optind;
		int longidx = 0;
		int c;

		c = getopt_long(argc, argv, optstring, longopts, &longidx);
		if (-1 == c)
			break; /* got '--' or end of arg list */

		switch (c) {
		case opt_binary:
			opt->binary = true;
			break;

		case opt_params:
			opt->params = true;
			break;

		case opt_help:
			opt->help = true;
			break;

		case opt_kstart:
			GET_VALUE(u64, optarg, &opt->kstart);
			break;

		case opt_errcnt:
			GET_VALUE(u32, optarg, &opt->errcnt);
			if (opt->errcnt == 0)
				opt->errcnt = (1L<<32) - 1;
			break;

		case opt_verbose:
			if (optarg)
				GET_VALUE(int, optarg, &verbose);
			else
				++verbose;
			opt->show_ops = (verbose > 1);
			break;

		case opt_version:
			opt->version = true;
			break;

		case opt_keys:
			GET_VALUE(u64, optarg, &opt->keys);
			break;

		case opt_klen:
			GET_VALUE(uint, optarg, &opt->klen);
			break;

		case opt_vlen:
			GET_VALUE(uint, optarg, &opt->vlen);
			break;

		case opt_threads:
			GET_VALUE(uint, optarg, &opt->threads);
			break;

		case opt_dryrun:
			opt->dryrun = true;
			break;

		case opt_do_put:
			opt->do_put  = true;
			opt->do_all = false;
			break;

		case opt_do_vput:
			opt->do_vput = true;
			opt->do_all = false;
			break;

		case opt_do_up:
			opt->do_up   = true;
			opt->do_all = false;
			break;

		case opt_do_vup:
			opt->do_vup  = true;
			opt->do_all = false;
			break;

		case opt_do_del:
			opt->do_del  = true;
			opt->do_all = false;
			break;

		case opt_do_pdel:
			opt->do_pdel  = true;
			break;

		case opt_do_vdel:
			opt->do_vdel = true;
			opt->do_all = false;
			break;

		case opt_sync:
			opt->sync = true;
			break;

		case opt_ckvs:
			opt->ckvs = true;
			break;

		case opt_ckvdb:
			opt->ckvdb = true;
			break;

		case opt_unclean:
			opt->unclean = true;
			break;

		case ':':
			syntax("missing argument for option '%s'",
			       argv[curind]);
			break;

		case '?':
			syntax("invalid option '%s'", argv[optind-1]);
			break;

		default:
			if (c == 0) {
				if (!longopt[longidx].flag) {
					syntax("unhandled option '--%s'",
					       longopts[longidx].name);
				}
			} else {
				syntax("unhandled option '%s'", argv[curind]);
			}
			break;
		}
	}

	if (opt->help)
		usage();
	else if (opt->version) {
		printf("HSE KVDB Lib:   %s\n", hse_kvdb_version_string());
		printf("HSE KVDB Tools: %s\n", hse_version);
	}

	if (opt->params)
		rparam_usage();

	*last_arg = optind;
}


void
rparam_usage(void)
{
	char buf[8192];

	fprintf(stderr, "\nTunable kvdb params:\n%s\n",
		hse_generate_help(buf, sizeof(buf), "kvdb_rparams"));

	fprintf(stderr, "\nTunable kvs params:\n%s\n",
		hse_generate_help(buf, sizeof(buf), "kvs_rparams"));
}

static void
usage(void)
{
	printf("usage: %s [options] <kvdb> <kvslist> [param=value ...]\n",
	       progname);
	printf("Key/value count and format:\n"
	       "  -t, --threads     number of threads\n"
	       "  -s, --kstart      starting index of keys, default=0\n"
	       "  -c, --keys COUNT  put/get COUNT keys\n"
	       "  -b, --binary      generate binary keys and values\n"
	       "  -l, --klen LEN    keys are LEN bytes\n"
	       "  -L, --vlen LEN    values are LEN bytes\n"
	       "Phases:\n"
	       "  -p, --put       put keys\n"
	       "  -u, --up        update keys\n"
	       "  -d, --del       delete keys\n"
	       "  -P, --vput      verify puts\n"
	       "  -U, --vup       verify updated keys\n"
	       "  -D, --vdel      verify deleted keys\n"
	       "  --sync          issue hse_kvdb_sync between phases\n"
	       "  --ckvs          close kvs between phases\n"
	       "  --ckvdb         close kvdb between phases\n"
	       "  --unclean       do not close kvs/kvdb at exit\n"
	       "  --pdel          use prefix deletes instead of point delete\n"
	       "Other:\n"
	       "  -e, --errcnt N     stop verify after N errors, 0=infinite\n"
	       "  -V, --version      print build version\n"
	       "  -v, --verbose=LVL  increase[or set] verbosity\n"
	       "  -C, --params       list tunable params (config vars)\n"
	       "  -h, --help         print this help list\n"
	       "  -n, --dryrun       show operations w/o executing them\n"
	       "\n");

	if (!verbose) {
		printf("Give -hv for more detail.\n\n");
		return;
	}

	printf("Mandatory parameters:\n"
	       "  <mpool>\n"
	       "  <kvdb>\n"
	       "  <kvslist> -- A kvs name, a comma or colon separated list\n"
	       "      of kvs names, a format string with a %%d conversion\n"
	       "      specifier that will be replaced with the logical\n"
	       "      thread ID, or any combination thereof.  The list is\n"
	       "      iterated over from left to right in round-robin\n"
	       "      fashion as each thread is created. Each kvsname may\n"
	       "      be preceded by a prefix followed by '/'.\n"
	       "      If using --pdel, make sure this prefix's len matches\n"
	       "      kvs's pfxlen\n"
	       "\n"
	       "Examples:\n"
	       "  putgetdel mp1 db1 kvs2\n"
	       "  putgetdel mp1 db1 kvs%%d\n"
	       "  putgetdel mp1 db1 foo:bar:baz\n"
	       "  putgetdel mp1 db1 kvs3 -t8 -c1000 "
	       "--put cn_compaction_debug=1\n"
	       "\n");
}

static void
add_error(const char *fmt, ...)
{
	char msg[256];
	va_list ap;

	++errors;

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	if (*msg)
		fprintf(stderr, "%s: %s\n", progname, msg);
}


void
bar_sync_init(uint count)
{
	int rc;
	char buf[64];

	rc = pthread_barrier_init(&barrier, NULL, count);
	if (rc)
		quit("Error: pthread_barrier_init: %s",
		     strerror_r(rc, buf, sizeof(buf)));
}


void
bar_sync(void)
{
	int rc;
	char buf[64];

	rc = pthread_barrier_wait(&barrier);
	if (rc && rc != PTHREAD_BARRIER_SERIAL_THREAD)
		quit("Error: pthread_barrier_wait: %s",
		     strerror_r(rc, buf, sizeof(buf)));
}


void
test_start_phase(struct thread_info *ti, char *message)
{
	u64 rc;

	printf("T%u: %s\n", ti->id, message);

	memset(ti->ref_key, 0, KLEN_MAX);
	memset(ti->ref_val, 0, VLEN_MAX);
	memset(ti->get_val, 0, VLEN_MAX);

	if (!kvdb) {
		if (verbose && ti->id == 0)
			printf("T%u: hse_kvdb_open %s\n", ti->id, opt.mpool);
		bar_sync();
		if (ti->id == 0) {
			if (!opt.dryrun) {
				rc = hse_kvdb_open(opt.mpool, params, &kvdb);
				if (rc)
					merr_quit("hse_kvdb_open failed", rc);
			} else {
				kvdb = (void *)1;
			}
		}
		bar_sync();
		assert(kvdb);
	}

	if (!ti->kvs) {
		if (verbose)
			printf("T%u: hse_kvdb_kvs_open %s\n", ti->id,
			       ti->kvs_name);
		if (!opt.dryrun) {
			rc = hse_kvdb_kvs_open(kvdb, ti->kvs_name,
					       params, &ti->kvs);
			if (rc)
				merr_quit("hse_kvdb_kvs_open failed", rc);
		} else {
			ti->kvs = (void *)1;
		}
		assert(ti->kvs);
	}
}

void
test_end_phase(struct thread_info *ti, bool final)
{
	bool ckvs = (final && opt.unclean) ? false : (final || opt.ckvs);
	bool ckvdb = (final && opt.unclean) ? false : (final || opt.ckvdb);
	u64  rc;

	if ((opt.sync && kvdb) || (final && opt.unclean)) {
		if (verbose)
			printf("T%u: hse_kvdb_sync\n", ti->id);
		if (!opt.dryrun) {
			rc = hse_kvdb_sync(kvdb);
			if (rc)
				merr_quit("hse_kvdb_sync failed", rc);
		}
	}

	if (ti->kvs && ckvs) {
		if (verbose)
			printf("T%u: hse_kvdb_kvs_close %s\n",
			       ti->id, ti->kvs_name);
		if (!opt.dryrun) {
			rc = hse_kvdb_kvs_close(ti->kvs);
			if (rc)
				merr_quit("hse_kvdb_kvs_close failed", rc);
		}
		ti->kvs = 0;
	}

	if (kvdb && ckvdb) {
		if (verbose && ti->id == 0)
			printf("T%u: hse_kvdb_close\n", ti->id);
		bar_sync();
		if (ti->id == 0) {
			if (!opt.dryrun) {
				rc = hse_kvdb_close(kvdb);
				if (rc)
					merr_quit("hse_kvdb_close failed", rc);
			}
			kvdb = 0;
		}
		ti->kvs = 0;
		bar_sync();
	}
}

void
fmt_string(
	char *str,
	int len,
	int max_len,
	char fill,
	char *fmt,
	u64 fmt_arg1,
	int fmt_arg2)
{
	int i;

	if (len > max_len)
		quit("key or value too large: %u (limit is %u)", len, max_len);

	snprintf(str, len, fmt, fmt_arg1, fmt_arg2);
	i = strlen(str);
	while (i+1 < len)
		str[i++] = fill;
	str[i] = '\0';
}

void
fmt_key(
	struct thread_info *ti,
	int len,
	unsigned long num)
{
	static u32 u;
	unsigned char *str = ti->ref_key;

	if (len < 3) {
		memcpy(str, "BAD", len);
		return;
	}

	if (key_gen) {
		get_key(key_gen, str, num);
		str[len-1] = 0;
	} else {
		*(u32 *)str = ++u;
		for (len -= 4, str += 4; len > 0; --len)
			*str++ = u & 255;
	}

	if (ti->pfxlen && ti->pfxlen < len)
		memcpy(ti->ref_key, ti->pfx, ti->pfxlen);
}

int key_showlen;
int val_showlen;

void
set_kv(
	struct thread_info          *ti,
	u64                        keynum,
	uint                       salt)
{
	if (opt.binary) {
		uint32_t *pdata = (uint32_t *)ti->ref_val;
		uint32_t *data = (uint32_t *)ti->ref_key;
		int idx;

		/* Each binary key/value is a function of the previous
		 * key/value.
		 */
		/*idx = keynum % (KLEN_MAX / sizeof(*data) - 32);*/
		idx = keynum % 8;
		ti->ref_klen = (idx + 1) * sizeof(*data);
		data[idx] = keynum;

		/*idx = keynum % (VLEN_MAX / 8 / sizeof(*pdata));*/
		idx = keynum % 32;
		ti->ref_vlen = (idx + 1) * sizeof(*pdata);
		pdata[idx] = keynum + salt;

		*(uint64_t *)ti->get_val = 0xdeadbeefabadcafe;

		return;
	}

	fmt_key(ti, opt.klen, keynum);

	if (opt.vlen > 0)
		fmt_string(ti->ref_val,
			   opt.vlen, VLEN_MAX, '*', VAL_PREFIX,
			   keynum, salt);

	ti->ref_klen     = opt.klen;
	ti->ref_vlen  = opt.vlen;

	key_showlen = ti->ref_klen;
	val_showlen = ti->ref_vlen;

	if (key_showlen > KEY_SHOWLEN)
		key_showlen = KEY_SHOWLEN;
	if (val_showlen > VAL_SHOWLEN)
		val_showlen = VAL_SHOWLEN;

	/*
	 * ti->get is the buffer for 'hse_kvs_get' results. Initialize it to
	 * something that will not match a key, and set vt_plen to the
	 * size of the buffer it points to.
	 */
	sprintf(ti->get_val, "**UNINITIALIZED_BUFFER**");
}

void
test_put(struct thread_info *ti, uint salt)
{
	u64 i, last_key;
	int rc;

	test_start_phase(ti, salt ? "Update existing keys" : "Insert new keys");

	last_key = opt.kstart + opt.keys;
	for (i = opt.kstart; i < last_key; i++) {
		set_kv(ti, i, salt);
		if (opt.show_ops) {
			printf("T%u: PUT(%lu,%u): key[%zu]=%.*s..."
			       " val[%zu]=%.*s...\n",
			       ti->id, i, salt, ti->ref_klen,
			       key_showlen,
			       (char *)ti->ref_key,
			       ti->ref_vlen,
			       val_showlen,
			       (char *)ti->ref_val);
		}

		if (opt.dryrun)
			continue;

		rc = hse_kvs_put(ti->kvs, NULL,
			     ti->ref_key, ti->ref_klen,
			     ti->ref_val, ti->ref_vlen);
		if (rc)
			merr_quit("kvdb_put failed", rc);
	}

	test_end_phase(ti, false);
}

void
test_delete(struct thread_info *ti)
{
	u64         i, last_key;
	uint        salt = -1; /* not important for delete */
	u64         rc;

	test_start_phase(ti, "Delete keys");

	last_key = opt.kstart + opt.keys;

	if (opt.do_pdel) {
		size_t plen = 0;

		rc = hse_kvs_prefix_delete(ti->kvs, NULL, ti->pfx, ti->pfxlen, &plen);
		if (!rc)
			goto done;
		if (plen)
			fprintf(stderr, "pfxlen (%d) did not match kvs pfxlen "
				"(%lu)\n", ti->pfxlen, plen);

		merr_quit("hse_kvs_prefix_delete failed", rc);
	}

	for (i = opt.kstart; i < last_key; i++) {
		set_kv(ti, i, salt);
		if (opt.show_ops)
			printf("T%u: DEL(%lu,NA): key[%zu]=%.*s...\n",
			       ti->id, i, ti->ref_klen,
			       key_showlen, (char *)ti->ref_key);

		if (opt.dryrun)
			continue;

		rc = hse_kvs_delete(ti->kvs, NULL, ti->ref_key, ti->ref_klen);
		if (rc)
			merr_quit("kvs_del failed", rc);
	}
done:
	test_end_phase(ti, false);
}


void
test_put_verify(struct thread_info *ti, uint salt)
{
	u64         i, last_key;
	size_t      get_vlen;
	void       *get_val = ti->get_val;

	test_start_phase(ti,
			 salt
			 ? "Verify updated keys"
			 : "Verify newly inserted keys");

	last_key = opt.kstart + opt.keys;
	for (i = opt.kstart; i < last_key; i++) {
		bool found = false;
		u64 rc;

		if (errors >= opt.errcnt)
			break;

		const char *key = (char *)ti->ref_key;

		set_kv(ti, i, salt);

		if (opt.show_ops)
			printf("T%u: VERIFY_PUT(%lu,%d): key[%zu]=%.*s...\n",
			       ti->id, i, salt, ti->ref_klen,
			       key_showlen, key);

		if (opt.dryrun)
			continue;

		get_vlen = (size_t)-1;
		rc = hse_kvs_get(ti->kvs, NULL, ti->ref_key,
			     ti->ref_klen, &found, get_val,
			     VLEN_MAX, &get_vlen);
		if (rc)
			merr_quit("hse_kvs_get failed", rc);

		if (!found) {
			add_error("key not found: key#%d[%zu]=%.*s%s",
			     i, ti->ref_klen,
			     key_showlen, key,
			     key_showlen < ti->ref_klen ? "..." : "");
			continue;
		}

		if (get_vlen != ti->ref_vlen) {
			add_error("vput: key found, but value has wrong length:"
				  " key#%d[%zu]=%.*s..."
				  " expected len=%zu got %zu",
				  i, ti->ref_klen,
				  key_showlen, key,
				  ti->ref_vlen,
				  get_vlen);
			continue;
		}

		if (opt.show_ops)
			printf("T%u: VERIFY_PUT(%lu,%d): val[%zu]=%.*s...\n",
			       ti->id, i, salt, get_vlen,
			       val_showlen, (char *)get_val);

		if (ti->ref_vlen > 0 &&
		    memcmp(get_val, ti->ref_val, ti->ref_vlen)) {
			add_error("vput: key found, but value wrong:"
				  " kvs %s: key#%d[%zu]=%.*s..."
				  " val[%zu]=%.*s..."
				  " expected %.*s",
				  ti->kvs_name, i, ti->ref_klen,
				  key_showlen, key,
				  ti->ref_vlen, val_showlen,
				  ti->ref_val,
				  val_showlen, get_val);
		}

	}

	test_end_phase(ti, false);
}

void
test_delete_verify(struct thread_info *ti)
{
	u64         i, last_key;
	uint        salt = -1; /* not important for delete */
	size_t      get_vlen;
	void       *get_val = ti->get_val;

	test_start_phase(ti, "Verify deleted keys");

	memset(ti->ref_key, 0, KLEN_MAX);
	memset(ti->ref_val, 0, VLEN_MAX);

	last_key = opt.kstart + opt.keys;
	for (i = opt.kstart; i < last_key; i++) {
		bool    found = false;
		u64     rc;

		if (errors >= opt.errcnt)
			break;

		set_kv(ti, i, salt);
		if (opt.show_ops)
			printf("T%u: VERIFY_DEL(%lu,NA): key[%zu]=%.*s...\n",
			       ti->id, i, ti->ref_klen,
			       key_showlen, (char *)ti->ref_key);
		if (opt.dryrun)
			continue;

		rc = hse_kvs_get(ti->kvs, NULL, ti->ref_key,
			     ti->ref_klen, &found, get_val,
			     VLEN_MAX, &get_vlen);
		if (rc)
			merr_quit("hse_kvs_get failed", rc);

		if (found) {
			add_error("found key after it was deleted:"
				  "key#%d[%zu]=%.*s%s",
				  i, ti->ref_klen, key_showlen,
				  (char *)ti->ref_key,
				  key_showlen < ti->ref_klen ? "..." : "");
		}
	}

	test_end_phase(ti, false);
}

void *
thread_main(void *arg)
{
	struct thread_info *ti = arg;
	uint salt;

	salt = 0;
	if (opt.do_all || opt.do_put)
		test_put(ti, salt);
	if (errors < opt.errcnt && (opt.do_all || opt.do_vput))
		test_put_verify(ti, salt);

	salt = 1;
	if (errors < opt.errcnt && (opt.do_all || opt.do_up))
		test_put(ti, salt);
	if (errors < opt.errcnt && (opt.do_all || opt.do_vup))
		test_put_verify(ti, salt);

	if (errors < opt.errcnt && (opt.do_all || opt.do_del))
		test_delete(ti);
	if (errors < opt.errcnt && (opt.do_all || opt.do_vdel))
		test_delete_verify(ti);

	test_end_phase(ti, true);

	if (errors >= opt.errcnt)
		quit("Exiting, because %u error(s) were encountered\n", errors);

	announce("Successful");

	return NULL;
}

int
main(int argc, char **argv)
{
	struct thread_info *threads = NULL;
	struct thread_info *ti;
	int               last_arg;
	char             *pctx; /* parse context */
	char             *cp;   /* generic char ptr */
	uint              kvsc;
	int               rc;
	uint              i;
	hse_err_t            err;

	gettimeofday(&tv_start, NULL);

	progname = strrchr(argv[0], '/');
	progname = progname ? progname + 1 : argv[0];

	err = hse_kvdb_init();
	if (err)
		quit("failed to initialize kvdb");

	options_default(&opt);
	options_parse(argc, argv, &opt, &last_arg);

	if (opt.version || opt.help || opt.params)
		goto done;

	hse_params_create(&params);

	err = hse_parse_cli(argc - last_arg, argv + last_arg,
			    &last_arg, 0, params);
	if (err) {
		rparam_usage();
		syntax("parameters could not be processed");
	}

	if (last_arg + 2 == argc) {
		opt.mpool = argv[last_arg++];
		opt.kvs   = argv[last_arg++];
	} else if (last_arg + 2 < argc) {
		syntax("extraneous argument: %s", argv[last_arg + 2]);
	} else {
		syntax("need mpool, kvdb and kvs names");
	}
	assert(opt.mpool && opt.kvs);

	if (!opt.keys)
		syntax("number of keys must be > 0");

	/* pgd expects null-terminated strings, thus klen-1 */
	key_gen = create_key_generator(key_space_size, opt.klen-1);
	if (!key_gen && opt.klen < 8)
		key_gen = create_key_generator(key_space_size/100, opt.klen-1);

	if (opt.threads == 0)
		opt.threads = 1;

	threads = calloc(opt.threads, sizeof(*threads));
	if (!threads)
		quit("unable to calloc %zu bytes for thread_info",
		     opt.threads * sizeof(*threads));

	bar_sync_init(opt.threads);

	/* Figure each thread's kvs name and kvs prefix.
	 * Example input with 5 threads:
	 *   "AA/foo_%d,ABC/bar_%d,dog_%d"
	 * Resulting kvs names and prefixes:
	 *	foo_0, pfx AA
	 *	bar_1, pfx ABC
	 *	dog_2, no pfx
	 *	foo_3, pfx AA
	 *	bar_2, pfx ABC
	 * First loop computes format strings, second loop
	 * converts them to kvs names.
	 */
	pctx = opt.kvs;
	kvsc = 0;
	for (i = 0, ti = threads; i < opt.threads; i++, ti++) {
		do {
			cp = strsep(&pctx, ":,; \t\r\n");
		} while (cp && !*cp);
		if (cp) {
			kvsc++;
			ti->kvs_name = cp;
			cp = strchr(ti->kvs_name, '/');
			if (cp) {
				if (cp[1] == 0)
					quit("prefix missing kvs: %s",
					     ti->kvs_name);
				*cp++ = 0;
				ti->pfx = ti->kvs_name;
				ti->pfxlen = strlen(ti->pfx);
				ti->kvs_name = cp;
			} else {
				ti->pfx = 0;
				ti->pfxlen = 0;
			}
		} else {
			/* use kvs name and prefix from thread i % kvsc */
			if (kvsc == 0)
				quit("Invalid kvs name: %s", opt.kvs);
			assert(i >= kvsc);
			ti->kvs_name = threads[i % kvsc].kvs_name;
			ti->pfx = threads[i % kvsc].pfx;
			ti->pfxlen = threads[i % kvsc].pfxlen;
		}
	}

	/* Convert format strings to kvs names */
	for (i = 0, ti = threads; i < opt.threads; i++, ti++) {
		int n;

		cp = ti->kvs_name;
		ti->kvs_name = 0;

		n = asprintf(&ti->kvs_name, cp, i);
		if (n <= 0)
			quit("cannot format kvs name: '%s'", cp);

		/* Ensure that no two threads are given the same kvs name. */
		for (n = 0; n < i; n++)
			if (!strcmp(ti->kvs_name, threads[n].kvs_name))
				quit("no two threads may work"
				     " on the same kvs: %s",
				     ti->kvs_name);
	}

	for (i = 0, ti = threads; i < opt.threads; i++, ti++) {
		ti->id = i;
		ti->ref_key = malloc(KLEN_MAX);
		ti->get_val = malloc(VLEN_MAX);
		ti->ref_val = malloc(VLEN_MAX);
		if (!ti->ref_key || !ti->get_val || !ti->ref_val)
			quit("Out of memory");
	}

	announce_header();

	/* Start the threads */
	for (i = 0, ti = threads; i < opt.threads; i++, ti++) {
		rc = pthread_create(&ti->tid, NULL, thread_main, ti);
		if (rc) {
			printf("%s: pthread_create failed: %s\n",
			       progname, strerror(rc));
			ti->joined = true;
			continue;
		}

		if (verbose > 1)
			printf("created thread %lu (%d)\n", ti->tid, ti->id);
	}

	/* If running as root, bump priority to help run-to-run consistency. */
	setpriority(PRIO_PROCESS, 0, -15);

	/* Reap all the threads. */
	for (i = 0, ti = threads; i < opt.threads; i++, ti++) {

		if (ti->joined)
			continue;

		rc = pthread_join(ti->tid, NULL);
		if (rc && rc != EINVAL && rc != ESRCH) {
			printf("%s: pthread_join failed: %s\n",
				progname, strerror(rc));
			continue;
		}

		if (verbose > 1)
			printf("joined thread %lu\n", ti->tid);
		ti->joined = true;
	}

	if (verbose) {
		struct timeval tv_stop;
		struct rusage rusage;

		gettimeofday(&tv_stop, NULL);

		rc = getrusage(RUSAGE_SELF, &rusage);
		if (rc == 0) {
			long utime, stime, rtime;

			rtime = (tv_stop.tv_sec - tv_start.tv_sec) * 1000000;
			rtime += (tv_stop.tv_usec - tv_start.tv_usec);
			utime = rusage.ru_utime.tv_sec * 1000000
				+ rusage.ru_utime.tv_usec;
			stime = rusage.ru_stime.tv_sec * 1000000
				+ rusage.ru_stime.tv_usec;

			printf("%s: resource usage:\n"
				"%12ld  real time (milliseconds)\n"
				"%12ld  user time (milliseconds)\n"
				"%12ld  system time (milliseconds)\n"
				"%12ld  max resident set size (KiB)\n"
				"%12ld  page reclaims\n"
				"%12ld  page faults\n"
				"%12ld  block input operations\n"
				"%12ld  block output operations\n"
				"%12ld  voluntary context switches\n"
				"%12ld  involuntary context switches\n",
				progname,
				rtime / 1000,
				utime / 1000,
				stime / 1000,
				rusage.ru_minflt,
				rusage.ru_majflt,
				rusage.ru_inblock,
				rusage.ru_oublock,
				rusage.ru_nvcsw,
				rusage.ru_nivcsw,
				rusage.ru_maxrss);
		}
	}

done:
	if (threads) {
		for (i = 0; i < opt.threads; i++) {
			free(threads[i].kvs_name);
			free(threads[i].ref_key);
			free(threads[i].ref_val);
			free(threads[i].get_val);
		}
		free(threads);
	}

	hse_params_destroy(params);
	destroy_key_generator(key_gen);

	hse_kvdb_fini();

	return errors == 0 ? 0 : -1;
}
