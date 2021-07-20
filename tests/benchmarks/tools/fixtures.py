import errno

from hse2 import hse

from tools import config


def create_kvdb():
    kvdb_home = config.KVDB_HOME
    kvs_name = config.KVS_NAME

    hse.init(kvdb_home)

    try:
        try:
            hse.Kvdb.create(kvdb_home)
        except hse.HseException as e:
            if e.returncode == errno.EEXIST:
                hse.Kvdb.drop(kvdb_home)
                hse.Kvdb.create(kvdb_home)
            else:
                raise e

        kvdb = hse.Kvdb.open(kvdb_home)

        try:
            kvdb.kvs_create(kvs_name)
        finally:
            kvdb.close()
    finally:
        hse.fini()
