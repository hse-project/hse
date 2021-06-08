This directory contains a modified implementation of `db_bench` based on the
1.23 release tag of LevelDB (<https://github.com/google/leveldb>) and commit
`9b3c03b3284f5886f9ef9a4ef703d57373e61be`.

The benchmarks are not changed except that LevelDB API calls were removed and
replaced with HSE API calls. Some options and benchmark types were removed if
they required LevelDB features with no equivalent in HSE.

Directory contents:
* `benchmarks` - The source code of the modified db_bench program
* `hse_binding` - Simple C++ layer over the HSE API to use the LevelDB `Slice`
and `Status` interfaces which are used frequently by db_bench.
    * This **is not** a drop in replacement for the LevelDB API.
* `include/leveldb` - Original LevelDB includes needed by db_bench: `slice.h`
and `status.h`.
* `port` - Original LevelDB code needed by db_bench: mutexes and condition
variables.
* `util` - Original LevelDB code needed by db_bench: histogram, mutex lock,
random number generator, compressible string generator, `Status` interface
implementation.
* `LICENSE` - The LevelDB copyright notice. (BSD 3-Clause)

Changes may be added in the future to support new features in HSE, or to port
in features from other implementations of db_bench.

How to run:
```
./db_bench
  --db=<path>
  --benchmarks=<comma separated list>
  --histogram=<0|1>
  --use_existing_db=<0|1>
  --num=<int>
  --reads=<int>
  --threads=<int>
  --value_size=<int>
  --compression_ratio=<decimal>
```

This example runs a sequential write benchmark to fill the KVS with 100
million records, then runs a random read benchmark on the same KVS:

```
./db_bench --db=mp1/kvs1 --num=100000000 --benchmarks=fillseq,readrandom
```

The following benchmarks are currently supported:
* fillseq
* fillrandom
* overwrite
* fill100K
* readseq
* readreverse
* readrandom
* readmissing
* seekrandom
* seekordered
* readhot
* readrandomsmall
* deleteseq
* deleterandom
* readwhilewriting
