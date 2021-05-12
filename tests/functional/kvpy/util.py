import argparse
import errno
from contextlib import contextmanager

import hse


def __get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kvdb-name", required=True)

    args = parser.parse_args()

    return args


def get_kvdb_name():
    args = __get_args()

    kvdb_name = args.kvdb_name

    return kvdb_name


def ensure_kvdb(kvdb_name: str, params: hse.Params) -> hse.Kvdb:
    try:
        hse.Kvdb.make(kvdb_name)
    except hse.KvdbException as e:
        if e.returncode == errno.EEXIST:
            pass
        else:
            raise e

    kvdb = hse.Kvdb.open(kvdb_name, params=params)

    return kvdb


def ensure_kvs(kvdb: hse.Kvdb, kvs_name: str, params: hse.Params) -> hse.Kvs:
    try:
        kvdb.kvs_make(kvs_name, params=params)
    except hse.KvdbException as e:
        if e.returncode == errno.EEXIST:
            kvdb.kvs_drop(kvs_name)
            kvdb.kvs_make(kvs_name, params=params)
        else:
            raise

    kvs = kvdb.kvs_open(kvs_name, params=params)

    return kvs


@contextmanager
def create_kvs(kvdb: hse.Kvdb, kvs_name: str, params: hse.Params):
    kvs = ensure_kvs(kvdb, kvs_name, params)

    try:
        yield kvs
    finally:
        kvs.close()
        kvdb.kvs_drop(kvs_name)


@contextmanager
def create_kvdb(kvdb_name: str, params: hse.Params):
    kvdb = ensure_kvdb(kvdb_name, params)

    try:
        yield kvdb
    finally:
        kvdb.close()
