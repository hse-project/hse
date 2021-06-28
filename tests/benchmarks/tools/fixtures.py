import errno

import hse

from tools import config


def create_kvdb():
    kvdb_home = config.KVDB_HOME
    kvs_name = config.KVS_NAME

    #
    # Until the mpool kernel module goes away, there is no way to drop and
    # recreate a KVDB without being root.  Just drop and recreate the KVS for now.
    #

    hse.init()

    try:
        try:
            hse.Kvdb.create(kvdb_home)
        except hse.KvdbException as e:
            if e.returncode == errno.EEXIST:
                pass
            else:
                raise e

        kvdb = hse.Kvdb.open(kvdb_home)

        try:
            for old_name in kvdb.names:
                kvdb.kvs_drop(old_name)

            kvdb.kvs_create(kvs_name)
        finally:
            kvdb.close()
    finally:
        hse.fini()
