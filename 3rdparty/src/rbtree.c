/* SPDX-License-Identifier: BSD-2-Clause */

/* This file contains extensions to a 3rdparty implemention of a red-black tree
 * data structure.  The red-black tree source code is in the following files:
 *   - include/3rdparty/rbtree.h
 *   - include/3rdparty/rbtree_types.h
 */

#include <3rdparty/rbtree_types.h>
#include <hse_util/assert.h>

int
rbtree_panic_cmp(struct rb_node *one, struct rb_node *two)
{
	assert(0);
	return 0;
}

RB_GENERATE(linux_root, rb_node, __entry, rbtree_panic_cmp);

#include <3rdparty/rbtree.h>

static struct rb_node *
rb_left_deepest_node(const struct rb_node *node)
{
	for (;;) {
		if (node->rb_left)
			node = node->rb_left;
		else if (node->rb_right)
			node = node->rb_right;
		else
			return (struct rb_node *)node;
	}
}

struct rb_node *
rb_next_postorder(const struct rb_node *node)
{
	const struct rb_node *parent;

	if (!node)
		return NULL;

	parent = rb_parent(node);

	/* If we're sitting on node, we've already seen our children */
	if (parent && node == parent->rb_left && parent->rb_right) {
		/* If we are the parent's left node, go to the parent's right
		 * node then all the way down to the left */
		return rb_left_deepest_node(parent->rb_right);
	}

	/* Otherwise we are the parent's right node, and the parent
	 * should be next.
	 */
	return (struct rb_node *)parent;
}

struct rb_node *
rb_first_postorder(const struct rb_root *root)
{
	if (!root->rb_node)
		return NULL;

	return rb_left_deepest_node(root->rb_node);
}
