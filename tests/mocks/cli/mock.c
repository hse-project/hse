/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include <clang-c/Index.h>
#include <clang-c/CXCompilationDatabase.h>

#include <hse/util/compiler.h>

#include "mkmock.h"
#include "mock.h"

size_t num_mocks;
size_t cap_mocks;
struct mock *mocks;

static void
read_return_type(CXCursor cursor, char **name, enum CXTypeKind *kind)
{
    CXType return_type = clang_getCursorResultType(cursor);
    CXString return_type_spelling = clang_getTypeSpelling(return_type);
    const char *return_type_spelling_data = clang_getCString(return_type_spelling);

    *name = strdup(return_type_spelling_data);
    *kind = return_type.kind;

    clang_disposeString(return_type_spelling);
}

static char *
read_name(CXCursor cursor)
{
    char *data;

    CXString spelling = clang_getCursorSpelling(cursor);
    const char *spelling_data = clang_getCString(spelling);

    data = strdup(spelling_data);

    clang_disposeString(spelling);

    return data;
}

static enum CXChildVisitResult
visit_function(CXCursor cursor, CXCursor parent HSE_MAYBE_UNUSED, CXClientData mock_function)
{
    switch (cursor.kind) {
        case CXCursor_AnnotateAttr: {
            CXString spelling = clang_getCursorSpelling(cursor);
            const char *spelling_data = clang_getCString(spelling);
            if (strcmp(spelling_data, "mock") == 0)
                *(bool *)mock_function = true;

            clang_disposeString(spelling);
        }
        /* fall through */
        default:
            return CXChildVisit_Continue;
    }
}

static void
visited_function(
    CXCursor cursor,
    CXCursor parent HSE_MAYBE_UNUSED,
    CXClientData client_data HSE_MAYBE_UNUSED)
{
    struct mock *mock;
    CXSourceLocation location;
    bool mock_function = false;

    /* Don't try to analyze system functions, and keep analysis within the main
     * file in order to avoid duplicate mock entries upon expansion of the
     * preprocessor.
     */
    location = clang_getCursorLocation(cursor);
    if (clang_Location_isInSystemHeader(location) || !clang_Location_isFromMainFile(location))
        return;

    clang_visitChildren(cursor, visit_function, &mock_function);
    if (!mock_function)
        return;

    if (cap_mocks == num_mocks) {
        cap_mocks *= 2;

        mocks = realloc(mocks, sizeof(*mocks) * cap_mocks);
        if (!mocks) {
            fprintf(stderr, "Ran out of memory\n");
            exit(EX_OSERR);
        }
    }

    mock = &mocks[num_mocks++];
    mock->argc = clang_Cursor_getNumArguments(cursor);
    read_return_type(cursor, &mock->return_type_name, &mock->return_type_kind);
    mock->function_name = read_name(cursor);
    mock->argv = malloc(mock->argc * sizeof(*mock->argv));
    if (!mock->return_type_name || !mock->function_name || !mock->argv) {
        fprintf(stderr, "Ran out of memory\n");
        exit(EX_OSERR);
    }

    for (size_t i = 0; i < mock->argc; i++) {
        CXType type;
        CXCursor arg;
        CXString arg_spelling;
        CXString type_spelling;
        struct argument *argument = &mock->argv[i];

        arg = clang_Cursor_getArgument(cursor, i);
        type = clang_getCursorType(arg);

        type_spelling = clang_getTypeSpelling(type);
        arg_spelling = clang_getCursorSpelling(arg);

        const char *type_spelling_data = clang_getCString(type_spelling);
        const char *argument_spelling_data = clang_getCString(arg_spelling);

        argument->type = strdup(type_spelling_data);
        argument->name = strdup(argument_spelling_data);

        clang_disposeString(type_spelling);
        clang_disposeString(arg_spelling);

        if (!argument->type || !argument->name) {
            fprintf(stderr, "Ran out of memory\n");
            exit(EX_OSERR);
        }
    }

    mock->is_variadic = !!clang_Cursor_isVariadic(cursor);
}

static enum CXChildVisitResult
visit_tu(CXCursor cursor, CXCursor parent, CXClientData client_data)
{
    switch (cursor.kind) {
        case CXCursor_FunctionDecl:
            visited_function(cursor, parent, client_data);
            /* fall through */
        default:
            return CXChildVisit_Continue;
    }

    return CXChildVisit_Continue;
}

int
mock_init()
{
    cap_mocks = 8;
    mocks = malloc(sizeof(*mocks) * cap_mocks);
    if (!mocks) {
        fprintf(stderr, "Ran out of memory\n");
        return ENOMEM;
    }

    return 0;
}

void
mock_fini()
{
    for (size_t i = 0; i < num_mocks; i++) {
        const struct mock *mock = &mocks[i];

        free(mock->return_type_name);
        free(mock->function_name);

        for (size_t j = 0; j < mock->argc; j++) {
            const struct argument *arg = &mock->argv[j];

            free(arg->type);
            free(arg->name);
        }
        free(mock->argv);
    }
    free(mocks);
}

int
mock_collect(const char *file)
{
    char **argv;
    CXIndex index;
    CXCursor cursor;
    unsigned int argc;
    enum CXErrorCode ret;
    CXTranslationUnit tu;
    CXCompileCommand command;
    unsigned int real_argc = 0;
    CXCompileCommands commands;

    commands = clang_CompilationDatabase_getCompileCommands(database, file);
    if (clang_CompileCommands_getSize(commands) != 1) {
        fprintf(stderr, "More than one series of compile commands detected for %s\n", file);
        return EX_SOFTWARE;
    }
    command = clang_CompileCommands_getCommand(commands, 0);

    argc = clang_CompileCommand_getNumArgs(command);
    argv = calloc(argc + 3, sizeof(*argv));
    for (unsigned int i = 0; i < argc; i++) {
        CXString arg = clang_CompileCommand_getArg(command, i);
        const char *arg_data = clang_getCString(arg);

        /* Ignore warnings */
        if (strstr(arg_data, "-W") == arg_data)
            continue;

        argv[real_argc++] = strdup(arg_data);

        clang_disposeString(arg);
    }
    argv[real_argc++] = "-DHSE_MOCK=__attribute__((__annotate__(\"mock\")))";
    argv[real_argc++] = "-I";
    argv[real_argc++] = includedir;

    for (unsigned int i = 0; i < real_argc; i++)
        printf("%s\n", argv[i]);

    index = clang_createIndex(0, 1);
    ret = clang_parseTranslationUnit2FullArgv(index, NULL, (const char **)argv, real_argc, NULL, 0,
        CXTranslationUnit_SkipFunctionBodies, &tu);
    if (ret) {
        fprintf(stderr, "Failed to parse the translation unit: %d\n", ret);
        return EX_SOFTWARE;
    }

    cursor = clang_getTranslationUnitCursor(tu);
    clang_visitChildren(cursor, visit_tu, NULL);

    clang_disposeTranslationUnit(tu);
    clang_disposeIndex(index);
    clang_CompileCommands_dispose(commands);

    for (unsigned int i = 0; i < real_argc - 3; i++)
        free(argv[i]);
    free(argv);

    return 0;
}
