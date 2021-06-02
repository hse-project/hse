This directory contains a modified implementation of `db_bench` based on the
1.23 release tag of LevelDB (<https://github.com/google/leveldb>).

The benchmarks are not changed except that LevelDB API calls were removed and
replaced with HSE API calls. Some options and benchmark types were removed if
they required LevelDB features with no equivalent in HSE.

Changes may be added in the future to support new features in HSE, or to port
in features from other implementations of `db_bench`.

A few source and header files in the `include`, `port`, and `util` directories
are carried over from the LevelDB source because `db_bench` depends on them
extensively. 
