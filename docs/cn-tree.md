# cN Tree

The cN tree is a 2-level tree comprised of a root and leaves. Leaf nodes each
contain an exclusive range of keys and their associated values.

## Properties

### Tree

- `fanout`: Number of leaf nodes within the tree.
- `generation`: Input for max leaf node size calculation. Starts at 0.
- `num_joins`: Number of joins currently happening.
- `num_splits`: Number of splits currently happening.

Fanout must be limited in order to prevent the tiny kvset problem from becoming
unwieldy.

### Node

- `id`: Node ID.
- `num_kvsets`: Number of kvsets contained with the node.
- `kvsets`: List of kvsets.
- `size`: Size of the node.

#### Root

No root specific properties.

#### Leaf

- `dirty`: Indicator marking whether the node should be evaluated as a candidate
    for splitting.
- `min_key`: Minimum key within the range of the node.
- `max_key`: Maximum key within the range of the node.
- `ref_cnt`: Reference count of the node.

Together `min_key` and `max_key` are the edge keys of the node.

## Edge Map

The edge map is the authority on leaf nodes. It knows what nodes contain what
ranges of keys. In order to access a leaf node, one must ask the edge map for a
reference.

## Max Node Size

The root node of the tree has a consistent max size. The leaf nodes have a
variable max size. The max size of the leaves is variable because the fanout of
the tree is not infinite. If the max leaf node size was constant, then the tree
could only hold a specified amount of data. The max leaf node size can be
described using the following equation: `(1 << G) * Z`, where `G` is the tree's
generation and `Z` is the original max leaf node size.

## Splitting Nodes

When a node has grown larger than the configured node size, we will initiate a
split. At this point we need to signify to CNDB that we are starting a leaf
split. After taking a reference to the node, we must determine the edge keys for
the new nodes. The left node after the split will have the `min_key` of the
original node. The right node after the split will have the `max_key` of the
original node. The midpoint is the middle of the original node's keyspace.

At this point, we can construct the two new nodes. The two new nodes will exist
in a void until they are ready to be committed to the edge map, but we will be
building them with records along the way in cndb.

In order to split, iterate over all kvsets. Initially, we can check to see if a
kvset is contained entirely within either of the left node or the right node.
If so, move it into the respective node. If not, split the kvset on the midpoint
in in order to create 2 new kvsets in the new nodes, one for each of the nodes.

## Joining Nodes

Joining nodes is a much simpler operation than splitting. In order to split,
we first have to find a sequence of 2 or more nodes whose combined sizes are
less than or equal to the configured node size.

Once this sequence has been identified, we must take references to the nodes. We
take the `min_key` of the new joined node from left-most node in our sequence,
and then we take the `max_key` from the right-most node in our sequence. Given
that all the kvsets within each of the nodes, is within the range of keys
of the new nodes, we can simply move all the kvsets by writing CNDB entries.

## Tree State

The tree state can be thought of as a linked list of nodes with a length of
`N`. The tree state is always changing as splits and joins happen during the
course of normal operations. Given the number of joins, `J`, and the number of
splits, `S`, the next state of the tree can be calculated as <code>N<sub>1</sub>
= N<sub>0</sub> + S - J</code>, where `N`<sub>`0`</sub> is the current number of
leaf nodes in the tree.

## Maintenance Algorithm

1. Spill data from root into leaf nodes,
1. For each leaf that received new data, check the new size of the node.
1. If the new size is greater than or equal to max node size, then the node will
    be marked as dirty.
1. Determine whether it is a good time to split the dirty node.
1. If so, split.
1. In the event, the split would cause `N`<sub>`1`</sub> to be greater than or
    equal to max fanout, increment the tree's `generation` and perform enough
    join operations to get the fanout of the tree to 80% of the max fanout. Join
    operations can be queued because by incrementing `generation`, we have also
    incremented the max leaf node size. The original split operation we were
    working on can be aborted since the max leaf node size has grown.
<!--
TODO: How many JOIN operations should we queue up? I would hate to see this
become a garbage collector pause-like situation. 80% is arbitrary at the moment.
-->
1. After the splits have occurred, iterate over all nodes to find strings to
    join.
1. For every string of nodes found whose combined size is less than or equal to
    the max node size, join them.
