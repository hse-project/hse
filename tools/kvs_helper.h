#ifndef KVS_HELPER_H
#define KVS_HELPER_H

#include <stdint.h>
#include <stdlib.h>

#include <hse/hse.h>
#include <hse/hse_experimental.h>

void fatal(int err, char *fmt, ...);

typedef void kh_func(void *);

struct thread_arg {
	void         *arg;
	struct hse_kvdb  *kvdb;
	struct hse_kvs   *kvs;
	uint64_t seed;
};

void
kh_rparams(
	int                   *argc,
	char                ***argv,
	struct hse_params     *params);

struct hse_kvdb *
kh_init(
	const char           *mpool,
	struct hse_params    *params);

void
kh_fini(void);

enum kh_flags {
	KH_FLAG_DETACH = 0x01,
};

void
kh_wait(void);

void
kh_wait_all(void);

int
kh_register(
	const char           *kvs,
	enum kh_flags         flags,
	struct hse_params    *params,
	kh_func              *func,
	void                 *arg);

int
kh_register_multiple(
	int           kvs_cnt,
	const char  **kvs_vec,
	int           num_threads,
	void        **argv,
	kh_func      *func);

struct hse_kvs *
kh_get_kvs(
	const char           *name,
	struct hse_params    *params);

/* cursor helper functions */
struct hse_kvs_cursor *
kh_cursor_create(
	struct hse_kvs           *kvs,
	struct hse_kvdb_opspec   *os,
	void                 *pfx,
	size_t                pfxlen);

void
kh_cursor_update(
	struct hse_kvs_cursor    *cur,
	struct hse_kvdb_opspec   *os);

void
kh_cursor_seek(
	struct hse_kvs_cursor    *cur,
	void                 *key,
	size_t                klen);

void
kh_cursor_seek_limited(
	struct hse_kvs_cursor    *cur,
	void                 *from,
	size_t                from_len,
	void                 *to,
	size_t                to_len);

bool
kh_cursor_read(
	struct hse_kvs_cursor    *cur,
	const void          **key,
	size_t               *klen,
	const void          **val,
	size_t               *vlen);

void
kh_cursor_destroy(
	struct hse_kvs_cursor    *cur);

#endif /* KVS_HELPER_H */
