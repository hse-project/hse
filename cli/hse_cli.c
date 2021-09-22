/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2016-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <errno.h>
#include <getopt.h>
#include <grp.h>
#include <pwd.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <stdarg.h>
#include <assert.h>

#include <sys/types.h>

#include <hse/hse.h>
#include <hse/version.h>

#include <hse_util/parse_num.h>
#include <hse_util/yaml.h>
#include <hse_util/string.h>
#include <cli/param.h>

#include "cli_util.h"
#include "storage_profile.h"

#define OPTION_HELP                 \
    {                               \
        "-h, --help", "Print help" \
    }

#define CONFIG_KVS_PFX_LEN                                                  \
    {                                                                       \
        "prefix.length=<int>", "Set KVS prefix length, range [0..32], default: 0" \
    }

#define min(a, b)                  \
    ({                             \
        typeof(a) arg1 = (a);      \
        typeof(b) arg2 = (b);      \
        arg1 < arg2 ? arg1 : arg2; \
    })

#define max(a, b)                  \
    ({                             \
        typeof(a) arg1 = (a);      \
        typeof(b) arg2 = (b);      \
        arg1 > arg2 ? arg1 : arg2; \
    })

#define YAML_BUF_SIZE (16 * 1024)

typedef uint64_t hse_err_t;

#define INTERNAL_ERROR()                                                \
    do {                                                                \
        fprintf(stderr, "%s:%d: internal error\n", __FILE__, __LINE__); \
        assert(0);                                                      \
        exit(-1);                                                       \
    } while (0)

/* Max len of any individual command.  Not enforced.  It is only used
 * for sizing.  See CLI_CMD_PATH_LEN_MAX.
 */
#define CLI_CMD_NAME_LEN_MAX 32

/* CLI_MENU_DEPTH_MAX need to be exact, but it must be larger
 * than the actual max depth.  Current depth is 3, so use 4.
 */
#define CLI_MENU_DEPTH_MAX 4

/* CLI_CMD_PATH_LEN_MAX must be large enough to hold concatenated
 * command names along a path in the command tree from root to leaf.
 * If it is too small, it will be discovered during initialization and
 * an error will be raised by the INTERNAL_ERROR macro.
 */
#define CLI_CMD_PATH_LEN_MAX ((CLI_MENU_DEPTH_MAX * (CLI_CMD_NAME_LEN_MAX + 1)) + 1)

#define CLI_CMD_OPSTR_LEN_MAX 256

struct cli;
struct cli_cmd;

struct name_desc {
    char *name;
    char *desc;
};

struct cmd_spec {
    const char *           usagev[4];
    const struct name_desc optionv[8];
    const struct name_desc configv[8];
    const struct option    longoptv[8];
    const char *           extra_help[8];
};

typedef int(cli_cmd_func_t)(struct cli_cmd *self, struct cli *cli);

struct cli_cmd {
    const char *    cmd_name;
    const char *    cmd_describe;
    cli_cmd_func_t *cmd_main;
    struct cli_cmd *cmd_subcommandv;

    /* Initialized at runtime:
     */
    const struct cmd_spec *cmd_spec;
    char                   cmd_path[CLI_CMD_PATH_LEN_MAX];
};

struct cli {
    bool            hse_init;
    bool            help_show_all;
    const char *    config;
    struct cli_cmd *cmd;
    int             argc;
    char **         argv;
    int             optind;
    char            opstr[CLI_CMD_OPSTR_LEN_MAX];
};

/*****************************************************************
 * HSE KVDB commands:
 *    hse kvdb create
 *    hse kvdb drop
 *    hse kvdb info
 *    hse kvdb compact
 */
static cli_cmd_func_t cli_hse_kvdb_create;
static cli_cmd_func_t cli_hse_kvdb_drop;
static cli_cmd_func_t cli_hse_kvdb_info;
static cli_cmd_func_t cli_hse_kvdb_compact;
/* static cli_cmd_func_t cli_hse_kvdb_params; */
struct cli_cmd        cli_hse_kvdb_commands[] = {
    { "create", "Create a KVDB", cli_hse_kvdb_create, 0 },
    { "drop", "Drop a KVDB", cli_hse_kvdb_drop, 0 },
    { "info", "Display information for a KVDB", cli_hse_kvdb_info, 0 },
    { "compact", "Compact a KVDB", cli_hse_kvdb_compact, 0 },
    /* { "params", "Show configuration parameters for a KVDB", cli_hse_kvdb_params, 0 }, */
    { 0 },
};

/*****************************************************************
 * HSE KVS commands:
 *    hse kvs create
 *    hse kvs drop
 */
static cli_cmd_func_t cli_hse_kvs_create;
static cli_cmd_func_t cli_hse_kvs_drop;
struct cli_cmd        cli_hse_kvs_commands[] = {
    { "create", "Create a KVS", cli_hse_kvs_create, 0 },
    { "drop", "Drop a KVS", cli_hse_kvs_drop, 0 },
    { 0 },
};

/*****************************************************************
 * HSE Storage commands:
 *    hse storage add
 *    hse storage info
 *    hse storage profile
 */
static cli_cmd_func_t cli_hse_storage_add;
#ifdef HSE_EXPERIMENTAL
static cli_cmd_func_t cli_hse_storage_info;
#endif
static cli_cmd_func_t cli_hse_storage_profile;
struct cli_cmd        cli_hse_storage_commands[] = {
    { "add", "Add a new media class storage to an existing offline KVDB", cli_hse_storage_add, 0 },
#ifdef HSE_EXPERIMENTAL
    { "info", "Display storage stats for a KVDB", cli_hse_storage_info, 0 },
#endif
    { "profile", "Profile storage path to determine throttle policy", cli_hse_storage_profile, 0 },
    { 0 },
};

/*****************************************************************
 * HSE commands:
 *    hse version
 *    hse kvdb
 *    hse kvs
 */
static cli_cmd_func_t cli_hse_kvdb;
static cli_cmd_func_t cli_hse_kvs;
static cli_cmd_func_t cli_hse_storage;
struct cli_cmd        cli_hse_commands[] = {
    { "kvdb", "KVDB commands", cli_hse_kvdb, cli_hse_kvdb_commands },
    { "kvs", "KVS commands", cli_hse_kvs, cli_hse_kvs_commands },
    { "storage", "KVDB storage commands", cli_hse_storage, cli_hse_storage_commands },
    { 0 },
};

/****************************************************************
 * Root of command tree
 */
static cli_cmd_func_t cli_hse;
struct cli_cmd        cli_root = { "hse", "HSE command line interface", cli_hse, cli_hse_commands };

int verbosity;

/**
 * cmd_tree_set_paths() - walk comand tree to set paths
 *
 * Set @cmd_path of each @cli_cmd in the command tree.
 */
static int
cmd_tree_set_path_recurse(struct cli_cmd *self, int argc_max, int argc, const char **argv)
{
    struct cli_cmd *sub;
    size_t          n;

    if (argc == argc_max) {
        INTERNAL_ERROR();
        return -1;
    }

    argv[argc++] = self->cmd_name;

    self->cmd_path[0] = '\0';
    for (int i = 0; i < argc; i++) {
        strlcat(self->cmd_path, argv[i], sizeof(self->cmd_path));
        strlcat(self->cmd_path, " ", sizeof(self->cmd_path));
    }

    n = strlen(self->cmd_path);
    if (n + 1 == sizeof(self->cmd_path)) {
        INTERNAL_ERROR();
        return -1;
    }

    if (n == 0) {
        INTERNAL_ERROR();
        return -1;
    }

    if (self->cmd_path[n - 1] != ' ') {
        INTERNAL_ERROR();
        return -1;
    }

    self->cmd_path[n - 1] = '\0';

    for (sub = self->cmd_subcommandv; sub && sub->cmd_name; sub++) {
        if (cmd_tree_set_path_recurse(sub, argc_max, argc, argv)) {
            INTERNAL_ERROR();
            return -1;
        }
    }

    return 0;
}

static int
cmd_tree_set_paths(struct cli_cmd *root)
{
    const char *argv[CLI_MENU_DEPTH_MAX];

    return cmd_tree_set_path_recurse(root, CLI_MENU_DEPTH_MAX, 0, argv);
}

/**
 * cli_cmd_lookup() - find a command handler by name
 *
 * The table, @cmdv, must be terminated by an entry
 * with an @cmd_name==NULL.
 */
static struct cli_cmd *
cli_cmd_lookup(struct cli_cmd *cmdv, const char *name)
{
    struct cli_cmd *cmd;

    for (cmd = cmdv; cmd->cmd_name; cmd++)
        if (!strcmp(name, cmd->cmd_name))
            return cmd;

    return 0;
}

/**
 * cmd_print_help() - print help info for a command.
 *
 * If @sub_commands != 0, the subcomands will be listed.
 */
static void
cmd_print_help(struct cli_cmd *cmd, FILE *fp)
{
    const struct name_desc *nd;

    bool have_subs;
    int  i, width;
    int  ilvl = 0; /* current indent level */
    int  tabw = 2; /* spaces per indent level (ie, tab width) */

    have_subs = cmd->cmd_subcommandv && cmd->cmd_subcommandv->cmd_name;

    fprintf(fp, "Usage: %*s%s", ilvl * tabw, "", cmd->cmd_path);
    for (i = 0; cmd->cmd_spec->usagev[i]; i++)
        fprintf(fp, "%*s%s%s", i == 0 ? 1 : ((ilvl + 1) * tabw), "", cmd->cmd_spec->usagev[i],
            cmd->cmd_spec->usagev[i + 1] ? "\n" : "");

    nd = cmd->cmd_spec->optionv;
    width = 0;
    for (i = 0; nd[i].name; i++)
        width = max(width, strlen(nd[i].name));
    width += 4;
    width = max(width, 24);
    for (i = 0; nd[i].name; i++) {
        if (i == 0)
            fprintf(fp, "\n\n%*sOptions:\n", ilvl * tabw, "");
        fprintf(fp, "%*s%-*s%s%s", (ilvl + 1) * tabw, "", width,
            nd[i].name, nd[i].desc, nd[i + 1].name ? "\n" : "");
    }

    nd = cmd->cmd_spec->configv;
    width = 0;
    for (i = 0; nd[i].name; i++) {
        width = max(width, strlen(nd[i].name));
    }
    width += 4;
    width = max(width, 24);
    for (i = 0; nd[i].name; i++) {
        if (i == 0)
            fprintf(fp, "\n\n%*sParameters:\n", ilvl * tabw, "");
        fprintf(fp, "%*s%-*s%s%s", (ilvl + 1) * tabw, "", width,
            nd[i].name, nd[i].desc, nd[i + 1].name ? "\n" : "");
    }

    if (have_subs) {
        struct cli_cmd *sub;

        width = 0;
        for (sub = cmd->cmd_subcommandv; sub->cmd_name; sub++)
            width = max(width, strlen(sub->cmd_name));
        width += 4;
        width = max(width, 24);

        fprintf(fp, "\n\n%*sCommands:\n", ilvl * tabw, "");
        for (sub = cmd->cmd_subcommandv; sub->cmd_name; sub++) {
            fprintf(
                fp,
                "%*s%-*s%s%s",
                (ilvl + 1) * tabw,
                "",
                width,
                sub->cmd_name,
                sub->cmd_describe,
                (sub + 1)->cmd_name ? "\n" : "");
        }
    }

    for (i = 0; cmd->cmd_spec->extra_help[i]; i++) {
        const char *msg = cmd->cmd_spec->extra_help[i];
        if (i == 0)
            fprintf(fp, "\n\n");
        fprintf(fp, "%*s%s%s", ilvl * tabw, "", msg,
            cmd->cmd_spec->extra_help[i + 1] ? "\n" : "");
    }

    /* Final newline. All other prints should go before this. */
    fprintf(fp, "\n");
}

/**
 * cli_init() -- intialize a cli context
 */
static int
cli_init(struct cli *self, int argc, char **argv)
{
    memset(self, 0, sizeof(*self));
    self->argc = argc;
    self->argv = argv;

    return 0;
}

/**
 * cli_push() -- prepare to parse a sub-command
 */
static void
cli_push(struct cli *cli, struct cli_cmd *cmd)
{
    size_t i, sz;
    char * s;

    cli->cmd = cmd;

    if (cli->optind > cli->argc)
        INTERNAL_ERROR();

    sz = 3;
    for (i = 0; cli->cmd->cmd_spec->longoptv[i].name; i++)
        sz += 3;

    if (sz > sizeof(cli->opstr))
        INTERNAL_ERROR();

    s = cli->opstr;
    *s++ = '+';
    *s++ = ':';

    for (i = 0; cli->cmd->cmd_spec->longoptv[i].name; i++) {

        const struct option *lo = cli->cmd->cmd_spec->longoptv + i;

        if (!lo->flag && lo->val) {
            *s++ = lo->val;
            if (lo->has_arg > 0)
                *s++ = ':';
            if (lo->has_arg > 1)
                *s++ = ':';
        }
    }

    *s = '\0';
}

static int
cli_hook(struct cli *cli, struct cli_cmd *cmd, const struct cmd_spec *spec)
{
    cmd->cmd_spec = spec;

    if (cli->help_show_all) {
        struct cli_cmd *sub;
        cmd_print_help(cmd, stdout);
        for (sub = cmd->cmd_subcommandv; sub && sub->cmd_name; sub++)
            sub->cmd_main(sub, cli);
        return 1;
    }

    cli_push(cli, cmd);
    return 0;
}

/**
 * cli_getopt() -- run one iteration of getopt_long on the argument list
 */
static int
cli_getopt(struct cli *self)
{
    int c;
    int longind = -1;

    if (!self->argc)
        return -1;

    optind = self->optind;

    c = getopt_long(self->argc, self->argv, self->opstr, self->cmd->cmd_spec->longoptv, &longind);

    assert(optind <= self->argc);

    self->optind = optind;

    if (c == ':' || c == '?') {

        char name[32];

        if (longind >= 0)
            snprintf(name, sizeof(name), "--%s", self->cmd->cmd_spec->longoptv[longind].name);
        else if (optopt || (c && c != '?'))
            snprintf(name, sizeof(name), "-%c", optopt ?: c);
        else
            strlcpy(name, self->argv[optind - 1], sizeof(name));

        if (c == ':')
            fprintf(stderr, "%s: option '%s' requires an argument\n", self->cmd->cmd_path, name);
        else
            fprintf(
                stderr, "%s: invalid option '%s', use -h for help\n", self->cmd->cmd_path, name);
    }

    return c;
}

/**
 * cli_next_arg() -- get next arg, returns NULL if none left. Advances 'optind'.
 *
 * Note:
 * - Use this function to get fixed args (e.g., kvdb home)
 * - Do not use this function to get options such as '-v' (use cli_getopt() for that).
 */
static const char *
cli_next_arg(struct cli *cli)
{
    assert(cli->optind <= cli->argc);

    if (cli->optind < cli->argc)
        return cli->argv[cli->optind++];

    return NULL;
}

/**
 * print_hse_err() -- print details about an hse error
 */
static void
print_hse_err(struct cli *cli, const char *api, hse_err_t err)
{
    char msg[256];

    hse_strerror(err, msg, sizeof(msg));
    fprintf(stderr, "%s: error from %s: %s\n", cli->cmd->cmd_path, api, msg);
}

/**
 * cli_hse_init() -- call hse_init() if it hasn't already been called
 */

static int
cli_hse_init_impl(struct cli *cli, const char *const *const paramv, size_t paramc)
{
    hse_err_t   err;

    if (cli->hse_init)
        return 0;

    err = hse_init(cli->config, paramc, paramv);
    if (err) {
        print_hse_err(cli, "hse_init", err);
        return -1;
    }

    cli->hse_init = true;

    return 0;
}

static int
cli_hse_init(struct cli *cli)
{
    const char *paramv[] = { "logging.destination=stderr", "logging.level=3" };

    return cli_hse_init_impl(cli, paramv, NELEM(paramv));
}

static int
cli_hse_init_rest(struct cli *cli)
{
    const char *paramv[] = { "logging.enabled=false" };

    return cli_hse_init_impl(cli, paramv, NELEM(paramv));
}

/**
 * cli_hse_init() -- call hse_fini() if hse_init() has been called
 */
static void
cli_hse_fini(struct cli *cli)
{
    if (cli->hse_init)
        hse_fini();
    cli->hse_init = false;
}

static int
cli_hse_kvdb_create_impl(struct cli *cli, const char *const kvdb_home)
{
    const char **paramv = NULL;
    size_t       paramc = 0;
    hse_err_t    herr = 0;
    int          rc = 0;

    if (cli_hse_init(cli))
        return -1;

    rc = params_from_argv(cli->argc, cli->argv, &cli->optind, &paramc, &paramv, NULL);
    if (rc)
        goto done;

    if (cli->optind != cli->argc) {
        rc = EINVAL;
        fprintf(stderr, "Too many arguments passed on the command line\n");
        goto done;
    }

    herr = hse_kvdb_create(kvdb_home, paramc, paramv);
    if (herr) {
        switch (hse_err_to_errno(herr)) {
            case EINVAL:
                fprintf(
                    stderr,
                    "Failed to create the KVDB (%s). Potentially received an invalid KVDB home directory "
                    "or an invalid parameter.\n",
                    kvdb_home);
                break;
            case EEXIST:
                fprintf(
                    stderr,
                    "KVDB (%s) already exists. You can drop and "
                    "recreate the KVDB.\n",
                    kvdb_home);
                break;
            case ENOENT:
                fprintf(
                    stderr,
                    "Failed to create the KVDB (%s). Please ensure that the KVDB home and "
                    "any specified media class paths exist.\n",
                    kvdb_home);
                break;
            default:
                print_hse_err(cli, "hse_kvdb_create", herr);
                break;
        }
        goto done;
    }

    if (verbosity)
        printf("Successfully created the KVDB (%s)\n", kvdb_home);

done:
    free(paramv);
    return (herr || rc) ? -1 : 0;
}

static int
cli_hse_kvdb_drop_impl(struct cli *cli, const char *const kvdb_home)
{
    hse_err_t    herr = 0;
    int          rc = 0;

    assert(kvdb_home);

    if (cli_hse_init(cli))
        return -1;

    if (cli->optind != cli->argc) {
        rc = EINVAL;
        fprintf(stderr, "Too many arguments passed on the command line\n");
        goto done;
    }

    herr = hse_kvdb_drop(kvdb_home);
    if (herr) {
        if (hse_err_to_errno(herr) != ENOENT)
            print_hse_err(cli, "hse_kvdb_drop", herr);
        goto done;
    }

    if (verbosity)
        printf("Successfully dropped the KVDB (%s)\n", kvdb_home);

done:
    if (herr && hse_err_to_errno(herr) == ENOENT)
        fprintf(stderr, "Failed to drop the KVDB (%s) because it does not exist\n", kvdb_home);

    return (herr || rc) ? -1 : 0;
}

static int
cli_hse_kvdb_info_impl(struct cli *cli, const char *const kvdb_home)
{
    const char *paramv[] = { "read_only=true" };
    char        buf[YAML_BUF_SIZE];
    int         rc = 0;
    bool        exists;

    struct yaml_context yc = {
        .yaml_buf = buf,
        .yaml_buf_sz = sizeof(buf),
        .yaml_indent = 0,
        .yaml_offset = 0,
        .yaml_emit = yaml_print_and_rewind,
    };

    assert(kvdb_home);

    if (cli_hse_init_rest(cli))
        return -1;

    if (cli->optind != cli->argc) {
        fprintf(stderr, "Too many arguments passed on the command line\n");
        return EINVAL;
    }

    exists = kvdb_info_print(kvdb_home, NELEM(paramv), paramv, &yc);
    if (!exists) {
        fprintf(stderr, "No such KVDB (%s)\n", kvdb_home);
        rc = -1;
    }

    printf("%s", buf);

    return rc;
}

static int
cli_hse_kvdb_compact_impl(
    struct cli *cli,
    const char *home,
    bool        status,
    bool        cancel,
    uint32_t    timeout_secs)
{
    const char *req;

    /* check status first so '-sx' results in status
     * but not cancel.
     */
    if (status)
        req = "status";
    else if (cancel)
        req = "cancel";
    else
        req = "request";

    if (cli_hse_init_rest(cli))
        return -1;

    if (cli->optind != cli->argc) {
        fprintf(stderr, "Too many arguments passed on the command line\n");
        return EINVAL;
    }

    return kvdb_compact_request(home, req, timeout_secs);
}

static int
cli_hse_kvdb(struct cli_cmd *self, struct cli *cli)
{
    const struct cmd_spec spec = {
        .usagev =
            {
                "[options] <command> ...",
                NULL,
            },
        .optionv =
            {
                OPTION_HELP,
                { NULL },
            },
        .longoptv =
            {
                { "help", no_argument, 0, 'h' },
                { NULL },
            },
        .configv =
            {
                { NULL },
            },
    };

    const char *    sub_name;
    struct cli_cmd *sub_cmd;
    int             c;
    bool            help = false;

    if (cli_hook(cli, self, &spec))
        return 0;

    while (-1 != (c = cli_getopt(cli))) {
        switch (c) {
            case 'h':
                help = true;
                break;
            default:
                return EX_USAGE;
        }
    }

    sub_name = cli_next_arg(cli);
    if (!sub_name || help) {
        cmd_print_help(self, help ? stdout : stderr);
        return help ? 0 : EX_USAGE;
    }

    sub_cmd = cli_cmd_lookup(self->cmd_subcommandv, sub_name);
    if (!sub_cmd) {
        fprintf(stderr, "%s: invalid command '%s', use -h for help\n", self->cmd_path, sub_name);
        return EX_USAGE;
    }

    return sub_cmd->cmd_main(sub_cmd, cli);
}

static int
cli_hse_kvdb_create(struct cli_cmd *self, struct cli *cli)
{
    const struct cmd_spec spec = {
        .usagev =
            {
                "[options] <kvdb_home> [<param>=<value>]...",
                NULL,
            },
        .optionv =
            {
                OPTION_HELP,
                { NULL },
            },
        .longoptv =
            {
                { "help", no_argument, 0, 'h' },
                { NULL },
            },
        .configv =
            {
                { NULL },
            },
    };

    const char *kvdb_home = NULL;
    bool        help = false;
    int         c;

    if (cli_hook(cli, self, &spec))
        return 0;

    while (-1 != (c = cli_getopt(cli))) {
        switch (c) {
            case 'h':
                help = true;
                break;
            default:
                return EX_USAGE;
        }
    }

    kvdb_home = cli_next_arg(cli);

    if (!kvdb_home || help) {
        cmd_print_help(self, help ? stdout : stderr);
        return help ? 0 : EX_USAGE;
    }

    return cli_hse_kvdb_create_impl(cli, kvdb_home);
}

static int
cli_hse_kvdb_drop(struct cli_cmd *self, struct cli *cli)
{
    const struct cmd_spec spec = {
        .usagev =
            {
                "[options] <kvdb_home>",
                NULL,
            },
        .optionv =
            {
                OPTION_HELP,
                { NULL },
            },
        .longoptv =
            {
                { "help", no_argument, 0, 'h' },
                { NULL },
            },
        .configv =
            {
                { NULL },
            },
    };

    const char *kvdb_home = NULL;
    bool        help = false;
    int         c;

    if (cli_hook(cli, self, &spec))
        return 0;

    while (-1 != (c = cli_getopt(cli))) {
        switch (c) {
            case 'h':
                help = true;
                break;
            default:
                return EX_USAGE;
        }
    }

    kvdb_home = cli_next_arg(cli);

    if (!kvdb_home || help) {
        cmd_print_help(self, help ? stdout : stderr);
        return help ? 0 : EX_USAGE;
    }

    return cli_hse_kvdb_drop_impl(cli, kvdb_home);
}

static int
cli_hse_kvdb_info(struct cli_cmd *self, struct cli *cli)
{
    const struct cmd_spec spec = {
        .usagev =
            {
                "[options] <kvdb_home>",
                NULL,
            },
        .optionv =
            {
                OPTION_HELP,
                { "-v, --verbose", "Print KVDB details" },
                { NULL },
            },
        .longoptv =
            {
                { "help", no_argument, 0, 'h' },
                { "verbose", no_argument, 0, 'v' },
                { NULL },
            },
        .configv =
            {
                { NULL },
            },
    };

    const char *kvdb_home = NULL;
    bool        help = false;
    int         c;

    if (cli_hook(cli, self, &spec))
        return 0;

    while (-1 != (c = cli_getopt(cli))) {
        switch (c) {
            case 'h':
                help = true;
                break;
            case 'v':
                ++verbosity;
                break;
            default:
                return EX_USAGE;
        }
    }

    kvdb_home = cli_next_arg(cli);

    if (!kvdb_home || help) {
        cmd_print_help(self, help ? stdout : stderr);
        return help ? 0 : EX_USAGE;
    }

    return cli_hse_kvdb_info_impl(cli, kvdb_home);
}

static int
cli_hse_kvdb_compact(struct cli_cmd *self, struct cli *cli)
{
    const struct cmd_spec spec = {
        .usagev =
            {
                "[options] <kvdb_home>",
                NULL,
            },
        .optionv =
            {
                OPTION_HELP,
                { "-s, --status", "Get status of compaction request" },
                { "-t, --timeout=SECS", "Set compaction timeout in seconds" },
                { "-x, --cancel", "Cancel compaction request" },
                { NULL },
            },
        .longoptv =
            {
                { "help", no_argument, 0, 'h' },
                { "timeout", required_argument, 0, 't' },
                { "status", no_argument, 0, 's' },
                { "cancel", no_argument, 0, 'x' },
                { NULL },
            },
        .configv =
            {
                { NULL },
            },
        .extra_help = {
            "With no options, this will request KVDB compaction and wait until",
            "it completes or the timeout period has passed.  The default timeout",
            "is 300 seconds.",
            NULL,
        },
    };

    const char *kvdb_home = NULL;
    uint32_t    timeout_secs = 300;
    bool        status = false;
    bool        cancel = false;
    bool        help = false;
    int         c;

    if (cli_hook(cli, self, &spec))
        return 0;

    while (-1 != (c = cli_getopt(cli))) {
        switch (c) {
            case 'h':
                help = true;
                break;
            case 's':
                status = true;
                break;
            case 'x':
                cancel = true;
                break;
            case 't':
                if (parse_u32(optarg, &timeout_secs)) {
                    fprintf(
                        stderr,
                        "%s: unable to parse"
                        " '%s' as an unsigned 32-bit"
                        " scalar value\n",
                        self->cmd_path,
                        optarg);
                    return EX_USAGE;
                }
                break;
            default:
                return EX_USAGE;
        }
    }

    kvdb_home = cli_next_arg(cli);

    if (!kvdb_home || help) {
        cmd_print_help(self, help ? stdout : stderr);
        return help ? 0 : EX_USAGE;
    }

    return cli_hse_kvdb_compact_impl(cli, kvdb_home, status, cancel, timeout_secs);
}

// static int
// cli_hse_kvdb_params_impl(struct cli *cli, const char *home)
// {
//     const char *extra_arg;

//     if (cli_hse_init(cli))
//         return -1;

//     /* This command hits the REST interface, so we don't need or
//      * support config files or command line hse param settings.
//      */
//     extra_arg = cli_next_arg(cli);
//     if (extra_arg) {
//         fprintf(
//             stderr,
//             "%s: unexpected parameter: '%s', use -h for help.\n",
//             cli->cmd->cmd_path,
//             extra_arg);
//         return EX_USAGE;
//     }

//     return hse_kvdb_params(home, true);
// }

// static int
// cli_hse_kvdb_params(struct cli_cmd *self, struct cli *cli)
// {
//     const struct cmd_spec spec = {
//         .usagev =
//             {
//                 "[options]",
//                 NULL,
//             },
//         .optionv =
//             {
//                 OPTION_HELP,
//                 { NULL },
//             },
//         .longoptv =
//             {
//                 { "help", no_argument, 0, 'h' },
//                 { NULL },
//             },
//         .configv =
//             {
//                 { NULL },
//             },
//         .extra_help = {
//             "Only operates on KVDBs that are currently open by another application.",
//             "Shows configuration parameter settings for the KVDB and for all KVSes",
//             "that the application has open.",
//             NULL,
//         },
//     };

//     bool help = false;
//     int  c;

//     if (cli_hook(cli, self, &spec))
//         return 0;

//     while (-1 != (c = cli_getopt(cli))) {
//         switch (c) {
//             case 'h':
//                 help = true;
//                 break;
//             default:
//                 return EX_USAGE;
//         }
//     }

//     if (help) {
//         cmd_print_help(self, stdout);
//         return 0;
//     }

//     return cli_hse_kvdb_params_impl(cli, kvdb_home);
// }

#ifdef HSE_EXPERIMENTAL
static int
cli_hse_storage_info_impl(struct cli *cli, const char *const kvdb_home)
{
    const char *paramv[] = { "read_only=true" };
    char        buf[YAML_BUF_SIZE];
    int         rc = 0;
    bool        exists;

    struct yaml_context yc = {
        .yaml_buf = buf,
        .yaml_buf_sz = sizeof(buf),
        .yaml_indent = 0,
        .yaml_offset = 0,
        .yaml_emit = yaml_print_and_rewind,
    };

    if (cli_hse_init_rest(cli))
        return -1;

    if (cli->optind != cli->argc) {
        fprintf(stderr, "Too many arguments passed on the command line\n");
        return EINVAL;
    }

    exists = kvdb_storage_info_print(kvdb_home, NELEM(paramv), paramv, &yc);
    if (!exists) {
        fprintf(stderr, "No such KVDB (%s)\n", kvdb_home);
        rc = -1;
    }

    printf("%s", buf);

    return rc;
}

static int
cli_hse_storage_info(struct cli_cmd *self, struct cli *cli)
{
    const struct cmd_spec spec = {
        .usagev =
            {
                "[options] <kvdb_home>",
                NULL,
            },
        .optionv =
            {
                OPTION_HELP,
                { NULL },
            },
        .longoptv =
            {
                { "help", no_argument, 0, 'h' },
                { NULL },
            },
        .configv =
            {
                { NULL },
            },
    };

    const char *kvdb_home = NULL;
    bool        help = false;
    int         c;

    if (cli_hook(cli, self, &spec))
        return 0;

    while (-1 != (c = cli_getopt(cli))) {
        switch (c) {
            case 'h':
                help = true;
                break;
            default:
                return EX_USAGE;
        }
    }

    kvdb_home = cli_next_arg(cli);

    if (!kvdb_home || help) {
        cmd_print_help(self, help ? stdout : stderr);
        return help ? 0 : EX_USAGE;
    }

    return cli_hse_storage_info_impl(cli, kvdb_home);
}
#endif

static int
cli_hse_storage_add_impl(struct cli *cli, const char *const kvdb_home)
{
    const char **paramv = NULL;
    size_t       paramc = 0;
    hse_err_t    herr = 0;
    int          rc = 0;

    assert(kvdb_home);

    if (cli_hse_init(cli))
        return -1;

    rc = params_from_argv(cli->argc, cli->argv, &cli->optind, &paramc, &paramv, NULL);
    if (rc)
        goto done;

    if (cli->optind != cli->argc) {
        rc = EINVAL;
        fprintf(stderr, "Too many arguments passed on the command line\n");
        goto done;
    }

    herr = hse_kvdb_storage_add(kvdb_home, paramc, paramv);
    if (herr) {
        switch (hse_err_to_errno(herr)) {
            case EINVAL:
                fprintf(
                    stderr,
                    "Failed to add storage to KVDB (%s).\nPotentially received an invalid "
                    "KVDB home directory or an invalid parameter.\n",
                    kvdb_home);
                break;
            case EEXIST:
                fprintf(
                    stderr,
                    "Failed to add storage to KVDB (%s).\nEither the media class already exists "
                    "or the specified media class path is already part of a KVDB.\n", kvdb_home);
                break;
            case ENOENT:
                fprintf(
                    stderr,
                    "Failed to add storage to the KVDB (%s).\nPlease ensure that the KVDB home and "
                    "any specified media class paths exist.\n",
                    kvdb_home);
                break;
            default:
                print_hse_err(cli, "hse_kvdb_storage_add", herr);
                break;
        }
        goto done;
    }

    if (verbosity)
        printf("Successfully added storage to the KVDB (%s)\n", kvdb_home);

done:
    free(paramv);

    return (herr || rc) ? -1 : 0;
}

static int
cli_hse_storage_add(struct cli_cmd *self, struct cli *cli)
{
    const struct cmd_spec spec = {
        .usagev =
            {
                "[options] <kvdb_home> [<param>=<value>]...",
                NULL,
            },
        .optionv =
            {
                OPTION_HELP,
                { NULL },
            },
        .longoptv =
            {
                { "help", no_argument, 0, 'h' },
                { NULL },
            },
        .configv =
            {
                { NULL },
            },
    };

    const char *kvdb_home = NULL;
    bool        help = false;
    int         c;

    if (cli_hook(cli, self, &spec))
        return 0;

    while (-1 != (c = cli_getopt(cli))) {
        switch (c) {
            case 'h':
                help = true;
                break;
            default:
                return EX_USAGE;
        }
    }

    kvdb_home = cli_next_arg(cli);

    if (!kvdb_home || help) {
        cmd_print_help(self, help ? stdout : stderr);
        return help ? 0 : EX_USAGE;
    }

    return cli_hse_storage_add_impl(cli, kvdb_home);
}

static int
cli_hse_storage_profile_impl(struct cli *cli, const char *path, bool quiet, bool verbose)
{
    if (cli_hse_init(cli))
        return -1;

    if (cli->optind != cli->argc) {
        fprintf(stderr, "Too many arguments passed on the command line\n");
        return EINVAL;
    }

    return hse_storage_profile(path, quiet, verbose);
}

static int
cli_hse_storage_profile(struct cli_cmd *self, struct cli *cli)
{
    const struct cmd_spec spec = {
        .usagev =
            {
                "[options] <storage_path>",
                NULL,
            },
        .optionv =
            {
                OPTION_HELP,
                { "-q, --quiet", "Outputs one of the following: [light, medium, default]" },
                { "-v, --verbose", "Verbose profile output" },
                { NULL },
            },
        .longoptv =
            {
                { "help", no_argument, 0, 'h' },
                { "quiet", no_argument, 0, 'q' },
                { "verbose", no_argument, 0, 'v' },
                { NULL },
            },
        .configv =
            {
                { NULL },
            },
    };

    const char *path = NULL;
    bool        help = false, quiet = false, verbose = false;
    int         c;

    if (cli_hook(cli, self, &spec))
        return 0;

    while (-1 != (c = cli_getopt(cli))) {
        switch (c) {
            case 'h':
                help = true;
                break;
            case 'q':
                quiet = true;
                break;
            case 'v':
                verbose = true;
                break;
            default:
                return EX_USAGE;
        }
    }

    path = cli_next_arg(cli);

    if (!path || help) {
        int rc = help ? 0 : EX_USAGE;

        cmd_print_help(self, help ? stdout : stderr);

        if (!verbose) {
            printf("\nUse -hv for more detail\n\n");
            return rc;
        }

        printf("\nThis tool creates a temp directory called \"storage_profile.tmp\" in the user\n");
        printf("specified <storage_path>. On completion/exit, this temp directory and its\n");
        printf("contents are deleted.\n\n");
        printf("If the tool abruptly terminates, this temp directory is left behind.\n");
        printf("A subsequent run will automatically clean up the temp directory,\n");
        printf("otherwise this directory needs to be manually removed.\n\n");
        printf("Running concurrent instances of profile sub-command is not supported.\n");

        return rc;
    }

    return cli_hse_storage_profile_impl(cli, path, quiet, verbose);
}

static int
cli_hse_storage(struct cli_cmd *self, struct cli *cli)
{
    const struct cmd_spec spec = {
        .usagev =
            {
                "[options] <command> ...",
                NULL,
            },
        .optionv =
            {
                OPTION_HELP,
                { NULL },
            },
        .longoptv =
            {
                { "help", no_argument, 0, 'h' },
                { NULL },
            },
        .configv =
            {
                { NULL },
            },
    };

    const char *    sub_name;
    struct cli_cmd *sub_cmd;
    int             c;
    bool            help = false;

    if (cli_hook(cli, self, &spec))
        return 0;

    while (-1 != (c = cli_getopt(cli))) {
        switch (c) {
            case 'h':
                help = true;
                break;
            default:
                return EX_USAGE;
        }
    }

    sub_name = cli_next_arg(cli);
    if (!sub_name || help) {
        cmd_print_help(self, help ? stdout : stderr);
        return help ? 0 : EX_USAGE;
    }

    sub_cmd = cli_cmd_lookup(self->cmd_subcommandv, sub_name);
    if (!sub_cmd) {
        fprintf(stderr, "%s: invalid command '%s', use -h for help\n", self->cmd_path, sub_name);
        return EX_USAGE;
    }

    return sub_cmd->cmd_main(sub_cmd, cli);
}

static int
cli_hse_kvs_create_impl(struct cli *cli, const char *const kvdb_home, const char *const kvs)
{
    /* Reduce throttle update period to improve kvdb close time.
     */
    const char *     kvdb_paramv[] = { "throttle_update_ns=3000000" };
    const char **    kvs_paramv = NULL;
    size_t           kvs_paramc = 0;
    struct hse_kvdb *db = 0;
    hse_err_t        herr = 0;
    int              rc = 0;

    assert(kvdb_home);
    assert(kvs);

    if (cli_hse_init(cli))
        return -1;

    rc = params_from_argv(cli->argc, cli->argv, &cli->optind, &kvs_paramc, &kvs_paramv, NULL);
    if (rc)
        goto done;

    if (cli->optind != cli->argc) {
        rc = EINVAL;
        fprintf(stderr, "Too many arguments passed on the command line\n");
        goto done;
    }

    herr = hse_kvdb_open(kvdb_home, NELEM(kvdb_paramv), kvdb_paramv, &db);
    if (herr) {
        switch (hse_err_to_errno(herr)) {
            case ENOENT:
                fprintf(
                    stderr,
                    "Failed to create the KVS (%s). The KVDB (%s) does not exist "
                    "or was previously partially created. Please drop and "
                    "recreate the KVDB. It may be required to run 'rm -rf %s/*'.\n",
                    kvs,
                    kvdb_home,
                    kvdb_home);
                break;
            default:
                print_hse_err(cli, "hse_kvdb_open", herr);
                break;
        }
        goto done;
    }

    herr = hse_kvdb_kvs_create(db, kvs, kvs_paramc, kvs_paramv);
    if (herr) {
        print_hse_err(cli, "hse_kvdb_kvs_create", herr);
        goto done;
    }

    if (verbosity)
        printf("Successfully created the KVS (%s)\n", kvs);

done:
    free(kvs_paramv);
    hse_kvdb_close(db);
    return (herr || rc) ? -1 : 0;
}

static int
cli_hse_kvs_drop_impl(struct cli *cli, const char *const kvdb_home, const char *const kvs)
{
    /* Reduce throttle update period to improve kvdb close time.
     */
    const char *     paramv[] = { "throttle_update_ns=3000000" };
    struct hse_kvdb *db = 0;
    hse_err_t        herr = 0;
    int              rc = 0;

    assert(kvdb_home);
    assert(kvs);

    if (cli_hse_init(cli))
        return -1;

    if (cli->optind != cli->argc) {
        rc = EINVAL;
        fprintf(stderr, "Too many arguments passed on the command line\n");
        goto done;
    }

    herr = hse_kvdb_open(kvdb_home, NELEM(paramv), paramv, &db);
    if (herr) {
        switch (hse_err_to_errno(herr)) {
            case ENOENT:
                fprintf(
                    stderr,
                    "KVDB (%s) does not exist or was partially created. Please drop and "
                    "recreate the KVDB. It may be required to run 'rm -rf %s/*'.\n",
                    kvdb_home,
                    kvdb_home);
                break;
            default:
                print_hse_err(cli, "hse_kvdb_open", herr);
                break;
        }
        goto done;
    }

    herr = hse_kvdb_kvs_drop(db, kvs);
    if (herr) {
        print_hse_err(cli, "hse_kvdb_kvs_drop", herr);
        goto done;
    }

    if (verbosity)
        printf("Successfully dropped the KVS (%s)\n", kvs);

done:
    hse_kvdb_close(db);
    return (herr || rc) ? -1 : 0;
}

static int
cli_hse_kvs_create(struct cli_cmd *self, struct cli *cli)
{
    const struct cmd_spec spec = {
        .usagev =
            {
                "[options] <kvdb_home> <kvs> [<param>=<value>]...",
                NULL,
            },
        .optionv =
            {
                OPTION_HELP,
                { NULL },
            },
        .longoptv =
            {
                { "help", no_argument, 0, 'h' },
                { NULL },
            },
        .configv =
            {
                CONFIG_KVS_PFX_LEN,
                { NULL },
            },
    };

    const char *kvdb_home = NULL;
    const char *kvs = NULL;
    bool        help = false;
    int         c, rc;

    if (cli_hook(cli, self, &spec))
        return 0;

    while (-1 != (c = cli_getopt(cli))) {
        switch (c) {
            case 'h':
                help = true;
                break;
            default:
                return EX_USAGE;
        }
    }

    kvdb_home = cli_next_arg(cli);
    kvs = cli_next_arg(cli);

    if (!kvdb_home || !kvs || help) {
        cmd_print_help(self, help ? stdout : stderr);
        return help ? 0 : EX_USAGE;
    }

    rc = cli_hse_kvs_create_impl(cli, kvdb_home, kvs);

    return rc;
}

static int
cli_hse_kvs_drop(struct cli_cmd *self, struct cli *cli)
{
    const struct cmd_spec spec = {
        .usagev =
            {
                "[options] <kvdb_home> <kvs>",
                NULL,
            },
        .optionv =
            {
                OPTION_HELP,
                { NULL },
            },
        .longoptv =
            {
                { "help", no_argument, 0, 'h' },
                { NULL },
            },
        .configv =
            {
                { NULL },
            },
    };

    const char *kvdb_home = NULL;
    const char *kvs = NULL;
    bool        help = false;
    int         c, rc;

    if (cli_hook(cli, self, &spec))
        return 0;

    while (-1 != (c = cli_getopt(cli))) {
        switch (c) {
            case 'h':
                help = true;
                break;
            default:
                return EX_USAGE;
        }
    }

    kvdb_home = cli_next_arg(cli);
    kvs = cli_next_arg(cli);

    if (!kvdb_home || !kvs || help) {
        cmd_print_help(self, help ? stdout : stderr);
        return help ? 0 : EX_USAGE;
    }

    rc = cli_hse_kvs_drop_impl(cli, kvdb_home, kvs);

    return rc;
}

static int
cli_hse_kvs(struct cli_cmd *self, struct cli *cli)
{
    const struct cmd_spec spec = {
        .usagev =
            {
                "[options] <command> ...",
                NULL,
            },
        .optionv =
            {
                OPTION_HELP,
                { NULL },
            },
        .longoptv =
            {
                { "help", no_argument, 0, 'h' },
                { NULL },
            },
        .configv =
            {
                { NULL },
            },
    };

    const char *    sub_name;
    struct cli_cmd *sub_cmd;
    int             c;
    bool            help = false;

    if (cli_hook(cli, self, &spec))
        return 0;

    while (-1 != (c = cli_getopt(cli))) {
        switch (c) {
            case 'h':
                help = true;
                break;
            default:
                return EX_USAGE;
        }
    }

    sub_name = cli_next_arg(cli);

    if (!sub_name || help) {
        cmd_print_help(self, help ? stdout : stderr);
        return help ? 0 : EX_USAGE;
    }

    sub_cmd = cli_cmd_lookup(self->cmd_subcommandv, sub_name);
    if (!sub_cmd) {
        fprintf(stderr, "%s: invalid command '%s', use -h for help\n", self->cmd_path, sub_name);
        return EX_USAGE;
    }

    return sub_cmd->cmd_main(sub_cmd, cli);
}

static int
cli_hse(struct cli_cmd *self, struct cli *cli)
{
    const struct cmd_spec spec = {
        .usagev =
            {
                "[options] <command> ...",
                NULL,
            },
        .optionv =
            {
                { "-h, --help",    "Print help (use -hv for more help)" },
                { "-v, --verbose", "Increase verbosity" },
                { "-V, --version", "Print version" },
                { "-Z, --config",  "Path to global configuration file" },
                { NULL },
            },
        .longoptv =
            {
                { "help", no_argument, 0, 'h' },
                { "verbose", no_argument, 0, 'v' },
                { "version", no_argument, 0, 'V' },
                { "config", required_argument, 0, 'Z' },
                { NULL },
            },
        .configv =
            {
                { NULL },
            },
        .extra_help = {
            "Examples:",
            "  hse kvdb -h                        # get help on KVDB commands",
            "  hse kvdb create path/to/kvdb       # create a KVDB in the specified directory",
            "  hse kvs create path/to/kvdb mykvs  # create a KVS in the specified KVDB home directory",
            NULL,
        },
    };

    const char *    sub_name;
    struct cli_cmd *sub_cmd;
    int             c;
    bool            help = false;
    bool            version = false;

    if (cli_hook(cli, self, &spec))
        return 0;

    while (-1 != (c = cli_getopt(cli))) {
        switch (c) {
            case 'h':
                help = true;
                break;
            case 'V':
                version = true;
                break;
            case 'v':
                ++verbosity;
                break;
            case 'Z':
                cli->config = optarg;
                break;
            default:
                return EX_USAGE;
        }
    }

    if (help) {
        /* show help for this command */
        cmd_print_help(self, stdout);
        return 0;
    }

    if (version) {
        if (verbosity) {
            printf("version: %s\n", HSE_VERSION_STRING);
            printf("build-configuration: %s\n", BUILD_CONFIG);
        } else {
            printf("%s\n", HSE_VERSION_STRING);
        }
        return 0;
    }

    sub_name = cli_next_arg(cli);
    if (!sub_name) {
        cmd_print_help(self, stderr);
        return EX_USAGE;
    }

    sub_cmd = cli_cmd_lookup(self->cmd_subcommandv, sub_name);
    if (!sub_cmd) {
        fprintf(stderr, "%s: invalid command '%s', use -h for help\n", self->cmd_path, sub_name);
        return EX_USAGE;
    }

    return sub_cmd->cmd_main(sub_cmd, cli);
}

int
main(int argc, char **argv)
{
    struct cli cli;
    char *     prog;
    int        rc;

    prog = strrchr(argv[0], '/');
    if (prog)
        argv[0] = prog + 1;

    cmd_tree_set_paths(&cli_root);

    rc = cli_init(&cli, argc, argv);
    if (rc)
        INTERNAL_ERROR();

    rc = cli_root.cmd_main(&cli_root, &cli);

    cli_hse_fini(&cli);

    return rc;
}
