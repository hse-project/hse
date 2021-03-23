import errno

import hse

from tools import config


def make_kvdb():
    kvdb_name = config.KVDB_NAME
    kvs_name = config.KVS_NAME

    #
    # Until the mpool kernel module goes away, there is no way to drop and
    # recreate a KVDB without being root.  Just drop and recreate the KVS for now.
    #

    hse.Kvdb.init()

    try:
        try:
            hse.Kvdb.make(kvdb_name)
        except hse.KvdbException as e:
            if e.returncode == errno.EEXIST:
                pass
            else:
                raise e

        kvdb = hse.Kvdb.open(kvdb_name)

        try:
            for old_name in kvdb.names:
                kvdb.kvs_drop(old_name)

            kvdb.kvs_make(kvs_name)
        finally:
            kvdb.close()
    finally:
        hse.Kvdb.fini()
