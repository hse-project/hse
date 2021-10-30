/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <rbtree.h>

#include <hse_util/xrand.h>

#include <hse_util/inttypes.h>
#include <hse_util/logging.h>

#include <mtf/framework.h>

int verbose = 0;

static struct rb_root tree;

struct entry {
    struct rb_node entry_node;
    int            key;
    int            value;
};

#define key2value(KEY) ((KEY) + 0x12340000)

struct test_set {
    int  num_entries;
    int *ordered_keys;
    int *shuffled_keys;
};

struct test_set *
test_set_create(int num_entries, u32 seed)
{
    struct xrand     xr;
    struct test_set *ts;
    int              key;
    int              i;

    if (num_entries < 0 || num_entries > 100000) {
        log_err("num_entries out of range!\n");
        exit(-1);
    }

    xrand_init(&xr, seed);

    ts = calloc(1, sizeof(struct test_set));
    if (!ts) {
        log_err("OUT OF MEMORY!\n");
        exit(-1);
    }

    ts->num_entries = num_entries;
    ts->ordered_keys = calloc(num_entries, sizeof(int));
    ts->shuffled_keys = calloc(num_entries, sizeof(int));

    if (!ts->ordered_keys || !ts->shuffled_keys) {
        log_err("OUT OF MEMORY!\n");
        exit(-1);
    }

    /* create list of ordered keys, save a copy in shuffled list too */
    key = 0;
    for (i = 0; i < num_entries; i++) {
        key += (int)xrand_range64(&xr, 1, 100);
        ts->ordered_keys[i] = key;
        ts->shuffled_keys[i] = key;
    }

    /* unbiased fisher yates */
    for (i = 0; i < (u32)num_entries; i++) {
        int tmp;
        u32 random_index = xrand_range64(&xr, i, (u32)num_entries);

        assert(random_index < num_entries); /* open-ended */
        tmp = ts->shuffled_keys[random_index];
        ts->shuffled_keys[random_index] = ts->shuffled_keys[i];
        ts->shuffled_keys[i] = tmp;
    }

    return ts;
}

void
test_set_destroy(struct test_set *ts)
{
    free(ts->ordered_keys);
    free(ts->shuffled_keys);
    free(ts);
}

void
test_set_print(struct test_set *ts)
{
    int i;

    log_info("Test set: %d entries\n", ts->num_entries);
    log_info("  %3s: %12s  %12s\n", "i", "ordered", "shuffled");

    for (i = 0; i < ts->num_entries; i++) {
        log_info("  %03d: %12d  %12d\n", i, ts->ordered_keys[i], ts->shuffled_keys[i]);
    }
}

static struct entry *
create_entry(int key, int value)
{

    struct entry *e = (struct entry *)calloc(1, sizeof(struct entry));

    e->key = key;
    e->value = value;

    return e;
}

static void
insert(int key, bool expect_success, struct mtf_test_info *lcl_ti)
{
    struct rb_node **link = &tree.rb_node;
    struct rb_node * parent = NULL;

    int  value = key2value(key);
    bool found = false;

    if (verbose)
        log_info("put %d -> %08x\n", key, value);

    while (*link) {
        struct entry *e;

        parent = *link;
        e = rb_entry(parent, struct entry, entry_node);

        if (key < e->key)
            link = &(*link)->rb_left;
        else if (key > e->key)
            link = &(*link)->rb_right;
        else {
            found = true;
            break;
        }
    }

    if (found)
        ASSERT_EQ(expect_success, false);
    else
        ASSERT_EQ(expect_success, true);

    if (!found) {
        struct entry *new_entry = create_entry(key, value);

        rb_link_node(&new_entry->entry_node, parent, link);
        rb_insert_color(&new_entry->entry_node, &tree);
    }
}

static void
_remove_entry(int key, bool expect_success, int value, struct mtf_test_info *lcl_ti)
{
    struct rb_node *node = tree.rb_node;
    struct entry *  entry = NULL;
    bool            found = false;

    /* Needed for ASSERT* macros */

    if (verbose)
        log_info("remove %d %d\n", key, expect_success);

    while (node) {
        entry = rb_entry(node, struct entry, entry_node);

        if (key < entry->key)
            node = node->rb_left;
        else if (key > entry->key)
            node = node->rb_right;
        else {
            found = true;
            break;
        }
    }

    ASSERT_EQ(found, expect_success);

    if (found) {
        ASSERT_EQ(value, entry->value);
        rb_erase(node, &tree.rb_node);
        free(entry);
    }
}

static void
remove_entry(int key, bool expect_success, struct mtf_test_info *lcl_ti)
{
    _remove_entry(key, expect_success, key2value(key), lcl_ti);
}

static void
lookup(int key, bool expect_success, struct mtf_test_info *lcl_ti)
{
    struct rb_node *node = tree.rb_node;
    struct entry *  entry = NULL;
    bool            found = false;

    if (verbose)
        log_info("lookup %d %d\n", key, expect_success);

    while (node) {
        entry = rb_entry(node, struct entry, entry_node);

        if (key < entry->key)
            node = node->rb_left;
        else if (key > entry->key)
            node = node->rb_right;
        else {
            found = true;
            break;
        }
    }

    ASSERT_EQ(found, expect_success);

    if (found) {
        int value = key2value(key);

        ASSERT_EQ(value, entry->value);
    }
}

static void
replace(int key, int new_value, struct mtf_test_info *lcl_ti)
{
    struct rb_node *node = tree.rb_node;
    struct entry *  entry = NULL;
    bool            found = false;

    if (verbose)
        log_info("replace %d\n", key);

    while (node) {
        entry = rb_entry(node, struct entry, entry_node);

        if (key < entry->key)
            node = node->rb_left;
        else if (key > entry->key)
            node = node->rb_right;
        else {
            found = true;
            break;
        }
    }

    ASSERT_EQ(found, true);

    struct entry *  new_entry = create_entry(key, new_value);
    struct rb_node *new_node = &new_entry->entry_node;

    rb_replace_node(node, new_node, &tree);

    /* free victim entry */
    free(entry);
}

#if 0
static
void
print_tree(void)
{
    struct rb_node *node;
    struct entry   *entry;
    int             i;

    for (i = 0, node = rb_first(&tree);
         node;
         node = rb_next(node), i++) {
        entry = rb_entry(node, struct entry, entry_node);
        log_info("%d: key %d val %08x\n",
                 i, entry->key, entry->value);
    }
}
#endif

int
test_case_pre(struct mtf_test_info *ti)
{
    tree = RB_ROOT;

    return 0;
}

int
test_case_post(struct mtf_test_info *ti)
{
    struct rb_node *node;

    for (node = rb_first(&tree); node; node = rb_next(node)) {
        struct entry *e = rb_entry(node, struct entry, entry_node);

        rb_erase(node, &tree.rb_node);
        free(e);
    }

    tree = RB_ROOT;

    return 0;
}

int
platform_pre(struct mtf_test_info *ti)
{
    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PRE(rbtree, platform_pre);

MTF_DEFINE_UTEST_PREPOST(rbtree, basic, test_case_pre, test_case_post)
{
    insert(0, true, lcl_ti);
    lookup(0, true, lcl_ti);
    remove_entry(0, true, lcl_ti);
}

MTF_DEFINE_UTEST_PREPOST(rbtree, insert_dups, test_case_pre, test_case_post)
{
    insert(0, true, lcl_ti);
    insert(0, false, lcl_ti);
    remove_entry(0, true, lcl_ti);
}

MTF_DEFINE_UTEST_PREPOST(rbtree, lookup_fail, test_case_pre, test_case_post)
{
    lookup(0, false, lcl_ti);
    insert(0, true, lcl_ti);
    lookup(0, true, lcl_ti);
    lookup(1, false, lcl_ti);
    remove_entry(0, true, lcl_ti);
}

MTF_DEFINE_UTEST_PREPOST(rbtree, remove_non_existing, test_case_pre, test_case_post)
{
    remove_entry(0, false, lcl_ti);
    remove_entry(1, false, lcl_ti);
    insert(2, true, lcl_ti);
    remove_entry(0, false, lcl_ti);
    remove_entry(1, false, lcl_ti);
    remove_entry(2, true, lcl_ti);
}

MTF_DEFINE_UTEST_PREPOST(rbtree, iterate, test_case_pre, test_case_post)
{
    int             i;
    int             count = 100;
    struct rb_node *node;
    struct entry *  entry;

    /* insert in order */
    for (i = 0; i < count; i++)
        insert(i, true, lcl_ti);

    /* iterate up */
    i = 0;
    for (node = rb_first(&tree); node; node = rb_next(node)) {
        entry = rb_entry(node, struct entry, entry_node);
        ASSERT_EQ(i, entry->key);
        ASSERT_EQ(key2value(i), entry->value);
        i += 1;
    }
    ASSERT_EQ(i, count);

    /* iterate down */
    i = count;
    for (node = rb_last(&tree); node; node = rb_prev(node)) {
        i -= 1;
        entry = rb_entry(node, struct entry, entry_node);
        ASSERT_EQ(i, entry->key);
        ASSERT_EQ(key2value(i), entry->value);
    }
    ASSERT_EQ(i, 0);

    /* remove */
    for (i = 0; i < count; i++)
        remove_entry(i, true, lcl_ti);
}

MTF_DEFINE_UTEST_PREPOST(rbtree, shuffle_test, test_case_pre, test_case_post)
{
    int i;
    int num_entries = 1000;
    u32 seed = 1111;

    struct rb_node * node;
    struct entry *   entry;
    struct test_set *ts;

    ts = test_set_create(num_entries, seed);
    ASSERT_TRUE(ts != NULL);

    /* insert in shuffled order */
    for (i = 0; i < num_entries; i++)
        insert(ts->shuffled_keys[i], true, lcl_ti);

    /* iterate to verify sorted order */
    i = 0;
    for (node = rb_first(&tree); node; node = rb_next(node)) {
        int key = ts->ordered_keys[i];

        entry = rb_entry(node, struct entry, entry_node);
        ASSERT_EQ(key, entry->key);
        ASSERT_EQ(key2value(key), entry->value);
        i += 1;
    }
    ASSERT_EQ(i, num_entries);

    /* remove in yet another order */
    for (i = num_entries - 1; i >= 0; i--)
        remove_entry(ts->shuffled_keys[i], true, lcl_ti);

    test_set_destroy(ts);
}

MTF_DEFINE_UTEST_PREPOST(rbtree, mixed, test_case_pre, test_case_post)
{
    int i;
    int num_entries = 1000;
    u32 seed = 2222;

    struct rb_node * node;
    struct entry *   entry;
    struct test_set *ts;

    ts = test_set_create(num_entries, seed);
    ASSERT_TRUE(ts != NULL);

    /* insert in shuffled order */
    for (i = 0; i < num_entries; i++) {
        int key = ts->shuffled_keys[i];

        insert(key, true, lcl_ti);
    }

    /* iterate to verify sorted order */
    i = 0;
    for (node = rb_first(&tree); node; node = rb_next(node)) {
        int key = ts->ordered_keys[i];

        entry = rb_entry(node, struct entry, entry_node);
        ASSERT_EQ(key, entry->key);
        ASSERT_EQ(key2value(key), entry->value);
        i += 1;
    }
    ASSERT_EQ(i, num_entries);

    /* try to insert duplicate */
    for (i = 0; i < num_entries; i += 10) {
        int key = ts->shuffled_keys[i];

        insert(key, false, lcl_ti); /* expect fail */
    }

    for (i = 0; i < num_entries; i += 15) {
        int key = ts->ordered_keys[i];

        /* key + 1 is probably not in rbtree */
        key += 1;

        /*
         * if in fact it is not in tree, then try to remove it
         * but expect failure
         */
        if (i + 1 == num_entries || key != ts->ordered_keys[i + 1])
            remove_entry(key, false, lcl_ti);
    }

    for (i = 0; i < num_entries; i++) {
        if (i % 10 == 3) {
            int key = ts->shuffled_keys[i];
            int new_value = key2value(key) + 1;

            replace(key, new_value, lcl_ti);
        }
    }

    /* remove in backward shuffle order */
    for (i = num_entries - 1; i >= 0; i--) {
        int key = ts->shuffled_keys[i];

        if (i % 10 == 3)
            _remove_entry(key, true, key2value(key) + 1, lcl_ti);
        else
            remove_entry(key, true, lcl_ti);
    }

    test_set_destroy(ts);
}

MTF_END_UTEST_COLLECTION(rbtree);
