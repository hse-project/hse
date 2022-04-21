# Compaction Merge Loops

Compaction operations transform a set of input kvsets into a set of new output
kvsets.  They are used are used to manage CN Tree shape (fanout, node size, node
length), and to control space amp (e.g., by eliminating deleted key-value
pairs).

There are three types of compaction operations:

- spill: consume one or more kvsets from the root node, produce at most one
  output kvset for each leaf node.
- kv-compact: consume two or more kvsets, produce one kvset
- k-compact: similar to kv-compact, but without compacting vblocks

HSE employs two additional operations that are an integral part of CN Tree
maintenance but strictly speaking are not compaction operations:

- split: split one kvset into two kvsets (used for node split)
- join: join two kvsets into one kvset (used for node join)

While split and join transform input kvsets into a set of new output kvsets,
they are metadata-only operations.  They don't rewrite kblocks or vblocks, and
they don't use compaction merge loops.  This document does not apply to split or
join operations.

Spill, k-compact and kv-compact operations follow these steps:

```
  1. read entries from one or more input kvsets
  2. merge input entries into a single stream of entries ordered by key
  3. read ordered stream of entries to produce a single output stream of entries
  4. write output entries to one or more output kvsets
  5. commit output kvsets, making them visible to queries
  6. remove input kvsets from the query path
  7. delete input kvsets

Figure 1: Compaction Steps
```

This document focuses on step 3, which is what we call the "merge loop" (i.e.,
the loop that processes the merged input stream).

## A Model

Each value has a type and sequence number. There are three value types: regular
(`V`), tombstone (`T`), and prefix tombstone (`PT`).  Since compaction logic cares
about value types and sequence numbers, but not actual values, the simplified
notation `<type><n>` can be used to represent a value with type `<type>` and
sequence number `<n>`.

Terminology:

- `value-type`: one of `V`, `T` or `PT`.
- `seqno`: an integer greater than 0 (lower seqnos indicate older values).
- `value`: a 2-tuple of `(value-type, seqno)`.
- `key`: a string with `length > 0`.
- `entry`: a `key` with one or more `values`.

Rules:

- A kvset contains 1 or more entries.
- A kvset cannot have two entries with the same key unless one entry has only
  `PT` values and the other has no `PT` values.

Observations:

- A kvset can have a `V` entry and a `PT` entry with the same key.

## Condensed Input Stream

We use the notion of a "condensed input stream" to be able to describe merge
loops at a higher level.

To understand what this means and why it is useful, consider the following two
kvsets:

```
    Kvset 1:
        Key    Values
        ----   -----
        foo    PT18
        foo1   V20, V16
        foo2   V14

    Kvset 2:
        Key    Values
        ----   -----
        foo1   T13, V12
        foo2   V11

Figure 2: Example input kvsets
```

In figure 1, step 2 produces a stream entries where each entry is a single entry
from a single kvset.  We call this the raw intput stream.  It would appear as
follows for these example kvsets:

```
    get_next_raw() -->   [ foo,  [ PT18 ]]
    get_next_raw() -->   [ foo1, [ V20, V16 ]]
    get_next_raw() -->   [ foo1, [ T13, V12 ]]
    get_next_raw() -->   [ foo2, [ V14 ]]
    get_next_raw() -->   [ foo2, [ V11 ]]

Figure 3: Raw input stream
```

The condensed view the same data is:

```
    get_next_condensed()  --> [ foo,  [ PT18 ]]
    get_next_condensed()  --> [ foo1, [ V20, V16, T13, V12, PT18 ]]
    get_next_condensed()  --> [ foo2, [ V14, V11, PT18 ]]

Figure 4: Condensed input stream
```

Observations on the condensed view:

- There has been no elimination of values.  It is simply a different view of the
  entries contained in the two input kvsets.
- Prefix tombstone `("foo", PT18)` is associated with all keys that match "foo".

In the condensed view, each key appears exactly once and with all of its values
and all prefix tombstones that match the key.  The logic of translating from the
raw stream to the condensed stream is not described here.

## Compaction Merge Logic

Using the condensed view abstraction, the logic of the merge loop is simple:

```
1: void compact(iterator *iter, u64 horizon, bool drop_tombs)
2: {
3:     while (entry = iter->get_next_condensed()) {
4:         key = entry.key();
5:         values = entry.values();
6:         decide which values should be kept;
7:         if (any values are kept) {
8:             output(key with kept values);
9:         }
10:    }
11: }

Figure 5: Accurate compaction merge loop logic
```

Note: This document does not aim to describe the exact structure of the
implementation, but rather the logic. For example, the implementation may or may
not directly implement the condensed view.

All that is left to complete the description of compaction merge logic is to
define the rules for value elimination logic (i.e., what happens at line 6 in
figure 5).

Some additional inputs to the loop are:

- `horizon`: a lower bound on the view seqno of all active queries and
  transactions
- `drop_tomb`: true if and only if the merge loop should drop tombstones and
  prefix tombstones

Input `drop_tomb` is set to true when the input kvsets include the last kvset in a
leaf node, in which case we know there are no older so the tombstones can be
dropped.

Value elimination rules:

1. Keep all values (`V`, `T`, and `PT`) with `seqno > horizon`.
1. If there is more than one value with `seqno <= horizon`, drop all but the one
   with the largest seqno.  Call the one with the largest seqno the "sunset"
   value.
1. If the sunset value is a `T` or a `PT` and `drop_tombs == true`, then drop the
   sunset value, otherwise keep it.

Implementation notes:

- As noted above, the actual merge loops use an iterator that produces the raw
  input stream.  As such, the loops contain a fair amount of logic to fabricate
  a condensed view from the raw view.

## TODO

- Describe tombstone propagation.
- Identify rules about the seqno ordering of values in each kvset entry.
