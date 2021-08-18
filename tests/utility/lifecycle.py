import errno
import os
from contextlib import ContextDecorator
from types import TracebackType
from typing import Iterable, Optional, Type, Union

from utility import cli
from hse2 import hse


class KvdbContext(ContextDecorator):
    def __init__(
        self,
        home: Optional[Union[str, "os.PathLike[str]"]] = cli.HOME,
        exists_ok: bool = True,
    ) -> None:
        super().__init__()
        self.__home = home
        self.__exists_ok = exists_ok
        self.__kvdb_cparams: Iterable[str] = ()
        self.__kvdb_rparams: Iterable[str] = ()

    def __enter__(self) -> hse.Kvdb:
        try:
            hse.Kvdb.create(self.__home, *self.__kvdb_cparams)
        except hse.HseException as e:
            if e.returncode != errno.EEXIST and self.__exists_ok:
                raise e
        self.__kvdb = hse.Kvdb.open(self.__home, *self.__kvdb_rparams)
        return self.__kvdb

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ):
        self.__kvdb.close()
        hse.Kvdb.drop(self.__home)

    def cparams(self, *params: str) -> "KvdbContext":
        self.__kvdb_cparams = params
        return self

    def rparams(self, *params: str) -> "KvdbContext":
        self.__kvdb_rparams = params
        return self


class KvsContext(ContextDecorator):
    def __init__(self, kvdb: hse.Kvdb, name: str, exists_ok: bool = True) -> None:
        super().__init__()
        self.__kvdb = kvdb
        self.__name = name
        self.__exists_ok = exists_ok
        self.__kvs_cparams: Iterable[str] = ()
        self.__kvs_rparams: Iterable[str] = ()

    def __enter__(self) -> hse.Kvs:
        try:
            self.__kvdb.kvs_create(self.__name, *self.__kvs_cparams)
        except hse.HseException as e:
            if e.returncode != errno.EEXIST and self.__exists_ok:
                raise e
        self.__kvs = self.__kvdb.kvs_open(self.__name, *self.__kvs_rparams)
        return self.__kvs

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ):
        self.__kvs.close()
        self.__kvdb.kvs_drop(self.__name)

    def cparams(self, *params: str) -> "KvsContext":
        self.__kvs_cparams = params
        return self

    def rparams(self, *params: str) -> "KvsContext":
        self.__kvs_rparams = params
        return self
