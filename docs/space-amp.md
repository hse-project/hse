# Space Amp

Space amp is loosely defined by the total storage space used to store a database
on media, divided by the total size of the user's data.  If a database has 1000
10-byte keys, each with 90 byte values, then size of the user's data is 100,000
bytes.  If the files that store this data use 131,072 of storage, then the space
amp is 1.31.

## Sources of Space Amp

There are two sources of space amp: overhead and garbage.

### Overhead Space Amp

Overhead space amp includes metadata and fragmentation.  Each storage layer
has its own overhead, for example:

- HSE overhead: mpool metadata, KVDB write ahead log, CNDB, kvset hblocks,
  kblock headers, wbtree leaf nodes, key and value metadata.
- Filesystem overhead: metadata, fragmentation.

Overhead space amp is determined by HSE's on-media data structures. As a result,
even a fully compacted KVDB will have space amp greater than 1.0.

### Garbage Space Amp

Key deletes and updates create garbage because the old keys and values cannot be
immediately deleted.  Sources of garbage in HSE include:

- Prefix tombstones: A prefix tombstone indicates that older keys matching the
  prefix have been logically deleted.  The older matching keys and their values
  are garbage.

- Key tombstones: A key tombstone indicates older exactly matching keys have
  been logically deleted.  All older versions of the key and their values are
  garbage.

- Duplicate keys: Duplicate keys are cause by updates to existing keys.  Older
  versions of the key and their values garbage.

- Unreferenced values: HSE's "k-compaction" operation combines multiple kvsets
  into one kvset, rewriting kblocks but not vblocks.  Keys may be garbage
  collected during k-compaction, but since vblocks are not rewritten, values
  associated with the deleted keys will remain in the vblocks as uncollected
  garbage.

## Garbage Tracked by HSE

HSE does not yet track prefix tombstone garbage.  We aim to address this in a
future release.

HSE uses the [HyperLogLog algorithm](https://en.wikipedia.org/wiki/HyperLogLog)
to estimate garbage from key tombstones and duplicate keys.  This type of garbage
is maintained at the CN tree node level.

HSE keeps track of the exact amount of unreferenced value data in each kvset as
well as in each CN tree node.
