/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>

#include <bsd/string.h>

#include <hse/error/merr.h>

#include <hse/tools/parm_groups.h>

struct grp {
    char        grp_name[PG_NAME_MAX];
    struct svec grp_svec;
    struct grp *grp_next;
};

struct parm_groups {
    struct grp *pg_grps;
    struct svec pg_store;
};

/*
 * Examples:
 *    pg_name_match("hse-gparams|gp", "hse-gparams") --> true
 *    pg_name_match("hse-gparams|gp", "gp") --> true
 *
 * Special case:
 *    pg_name_match("hse-gparams|gp", "hse-gparams|gp") --> true
 */
static bool
pg_name_match(const char *match_list, const char *name)
{
    const char *match;
    const char *match_end;
    size_t match_len;
    size_t name_len;

    if (!strcmp(name, match_list))
        return true;

    name_len = strlen(name);
    match = match_list;
    while (*match) {
        match_end = strchrnul(match, LIST_SEP_CHAR);
        match_len = match_end - match;
        if (match_len == name_len && !strncmp(name, match, name_len))
            return true;
        match = match_end;
        if (*match == LIST_SEP_CHAR)
            match++;
    }

    return false;
}


static struct svec *
pg_find_grp(struct parm_groups *self, const char *name)
{
    struct grp *g = self->pg_grps;

    while (g) {

        if (pg_name_match(g->grp_name, name))
            return &g->grp_svec;

        g = g->grp_next;
    }

    return NULL;
}

static merr_t
svec_add(struct svec *self, const char *str)
{
    if (self->strc == self->strc_max) {

        void *tmp;
        size_t new_max;

        new_max = 2 * self->strc_max;
        if (!new_max)
            new_max = 64;

        tmp = realloc(self->strv, new_max * sizeof(self->strv[0]));
        if (!tmp)
            return merr(ENOMEM);

        self->strv = tmp;
        self->strc_max = new_max;
    }

    assert(self->strc < self->strc_max);
    self->strv[self->strc++] = str;

    return 0;
}

void
svec_init(struct svec *self)
{
    self->strv = NULL;
    self->strc = 0;
    self->strc_max = 0;
}

static
void
svec_truncate(struct svec *self, size_t len, bool deep)
{
    for (size_t i = len; i < self->strc; i++) {
        if (deep)
            free((void *)self->strv[i]);
        self->strv[i] = NULL;
    }

    if (len < self->strc)
        self->strc = len;
}

static
void
svec_free(struct svec *self, bool deep)
{
    svec_truncate(self, 0, deep);
    free(self->strv);
    svec_init(self);
}

void
svec_reset(struct svec *self)
{
    svec_free(self, false);
}

merr_t
svec_append_svec(struct svec *self, ...)
{
    merr_t err = 0;
    struct svec *sv;
    size_t original_len;
    va_list ap;

    original_len = self->strc;

    va_start(ap, self);

    while (!err && NULL != (sv = va_arg(ap, struct svec *))) {
        for (size_t i = 0; !err && i < sv->strc; i++)
            err = svec_add(self, sv->strv[i]);
    }

    va_end(ap);

    if (err)
        svec_truncate(self, original_len, false);

    return err;
}

static merr_t
pg_add_str(struct parm_groups *self, struct svec *sv, const char *parm)
{
    merr_t err;
    char *parm_copy = NULL;

    parm_copy = strdup(parm);
    if (!parm_copy)
        return ENOMEM;

    err = svec_add(&self->pg_store, parm_copy);
    if (err) {
        free(parm_copy);
        return err;
    }

    /* No need to free parm_copy or remove it from the store on
     * failures after here.  Allocated parm_copy will be unused, but
     * it will be in the store and will be cleaned up in pg_destroy().
     */

    err = svec_add(sv, parm_copy);

    return err;
}

merr_t
svec_append_pg_impl(struct svec *self, struct parm_groups *pg, va_list ap)
{
    merr_t err = 0;
    struct svec sv;
    struct svec *sv_grp;
    void *arg;

    if (!pg)
        return merr(EINVAL);

    svec_init(&sv);

    while (!err && NULL != (arg = va_arg(ap, void *))) {
        if (NULL != (sv_grp = pg_find_grp(pg, arg)))
            err = svec_append_svec(&sv, sv_grp, NULL);
        else
            err = pg_add_str(pg, &sv, arg);
    }

    if (!err)
        err = svec_append_svec(self, &sv, NULL);

    svec_free(&sv, false);

    return err;
}

merr_t
svec_append_pg(struct svec *self, struct parm_groups *pg, ...)
{
    merr_t err;
    va_list ap;

    va_start(ap, pg);
    err = svec_append_pg_impl(self, pg, ap);
    va_end(ap);

    return err;
}

merr_t
pg_create(struct parm_groups **self_out, ...)
{
    merr_t err;
    va_list ap;
    const char *arg;
    struct parm_groups *self;

    self = calloc(1, sizeof(*self));
    if (!self)
        return merr(ENOMEM);

    va_start(ap, self_out);
    while (NULL != (arg = va_arg(ap, const char *))) {
        err = pg_define_group(self, arg);
        if (err)
            break;
    }
    va_end(ap);

    if (err) {
        pg_destroy(self);
        self = NULL;
    }

    *self_out = self;

    return err;
}

void
pg_destroy(struct parm_groups *self)
{
    struct grp *g, *next;

    if (!self)
        return;

    for (g = self->pg_grps; g; g = next) {
        next = g->grp_next;
        svec_free(&g->grp_svec, false);
        free(g);
    }

    svec_free(&self->pg_store, true);

    free(self);
}

merr_t
pg_define_group(struct parm_groups *self, const char *group_name)
{
    struct grp *g;

    if (pg_find_grp(self, group_name))
        return merr(EINVAL);

    g = calloc(1, sizeof(*g));
    if (!g)
        return merr(ENOMEM);

    if (strlcpy(g->grp_name, group_name, sizeof(g->grp_name)) >= sizeof(g->grp_name)) {
        free(g);
        return merr(ENAMETOOLONG);
    }

    g->grp_next = self->pg_grps;
    self->pg_grps = g;
    return 0;
}

merr_t
pg_set_parms(struct parm_groups *self, const char *group_name, ...)
{
    va_list ap;
    merr_t err = 0;
    const char *arg;
    struct svec *sv;

    sv = pg_find_grp(self, group_name);
    if (!sv)
        return merr(EINVAL);

    va_start(ap, group_name);

    while (!err && NULL != (arg = va_arg(ap, const char *)))
        err = pg_add_str(self, sv, arg);

    va_end(ap);

    return err;
}

merr_t
pg_svec_alloc(
    struct parm_groups *self,
    const char *        group_name,
    struct svec *       sv,
    ...)
{
    merr_t err = 0;
    struct svec sv_tmp = {};
    struct svec *sv_grp;
    va_list ap;
    const char *arg;

    sv_grp = pg_find_grp(self, group_name);
    if (!sv_grp)
        return EINVAL;

    for (size_t i = 0; !err && i < sv_grp->strc; i++)
        err = svec_add(&sv_tmp, sv_grp->strv[i]);

    va_start(ap, sv);
    while (!err && NULL != (arg = va_arg(ap, const char *)))
        err = pg_add_str(self, &sv_tmp, arg);
    va_end(ap);

    if (!err) {
        *sv = sv_tmp;
    } else {
        svec_free(&sv_tmp, false);
    }

    return err;
}

void
pg_svec_free(struct svec *sv)
{
    svec_free(sv, false);
}

merr_t
pg_parse_argv(struct parm_groups *self, int argc, char **argv, int *argx)
{
    struct svec *gsv = NULL;

    while (*argx < argc) {
        int err;
        const char *arg = argv[*argx];
        struct svec *tmp = pg_find_grp(self, arg);

        if (tmp) {
            /* save new group's svec and consume arg */
            gsv = tmp;
            *argx += 1;
            continue;
        }

        if (*arg == '-' || !strstr(arg, "="))
            break;

        if (!gsv)
            return EINVAL;

        /* add to group svec and consume arg */
        err = pg_add_str(self, gsv, arg);
        if (err)
            return err;

        *argx += 1;
    }

    return 0;
}
