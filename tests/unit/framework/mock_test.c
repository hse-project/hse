/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015 Micron Technology, Inc. All rights reserved.
 */

#include <hse_ut/framework.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* As long as we don't use MTF_END_UTEST_COLLECTION we don't get main() */

#define FAIL printf("Test case \"%s\" FAILED:\n  %s:%d\n", __FUNCTION__, __FILE__, __LINE__);

int
instantiate_mtf_test_coll_info()
{
    ___MTF_INNER_BEGIN_UTEST_COLLECTION_SHARED(frog, 0, 0);

    if (strcmp("frog", _mtf_frog_tci.tci_coll_name) != 0) {
        FAIL;
        return 0;
    }

    if (_mtf_frog_tci.tci_pre_run_hook != 0) {
        FAIL;
        return 0;
    }
    if (_mtf_frog_tci.tci_post_run_hook != 0) {
        FAIL;
        return 0;
    }
    if (_mtf_frog_tci.tci_state != ST_INITIALIZING) {
        FAIL;
        return 0;
    }
    if (_mtf_frog_tci.tci_res_rd_state != RD_READY) {
        FAIL;
        return 0;
    }
    if (_mtf_frog_tci.tci_res_rd_index != 0) {
        FAIL;
        return 0;
    }
    if (_mtf_frog_tci.tci_out_rd_state != RD_READY) {
        FAIL;
        return 0;
    }

    return 1;
}

int
probe_status_attribute()
{
    char          buffer[4096];
    unsigned long sz;

    ___MTF_INNER_BEGIN_UTEST_COLLECTION_SHARED(toad, 0, 0);

    sz = inner_attr_show(&_mtf_toad_tci, "status", buffer);
    if (strcmp("initializing\n", buffer) != 0) {
        FAIL;
        return 0;
    }
    if (sz != strlen(buffer)) {
        FAIL;
        return 0;
    }

    _mtf_toad_tci.tci_state = ST_READY;
    sz = inner_attr_show(&_mtf_toad_tci, "status", buffer);
    if (strcmp("ready\n", buffer) != 0) {
        FAIL;
        return 0;
    }
    if (sz != strlen(buffer)) {
        FAIL;
        return 0;
    }

    _mtf_toad_tci.tci_state = ST_RUNNING;
    sz = inner_attr_show(&_mtf_toad_tci, "status", buffer);
    if (strcmp("running\n", buffer) != 0) {
        FAIL;
        return 0;
    }
    if (sz != strlen(buffer)) {
        FAIL;
        return 0;
    }

    _mtf_toad_tci.tci_state = ST_DONE;
    sz = inner_attr_show(&_mtf_toad_tci, "status", buffer);
    if (strcmp("done\n", buffer) != 0) {
        FAIL;
        return 0;
    }
    if (sz != strlen(buffer)) {
        FAIL;
        return 0;
    }

    _mtf_toad_tci.tci_state = ST_ERROR;
    sz = inner_attr_show(&_mtf_toad_tci, "status", buffer);
    if (strcmp("error\n", buffer) != 0) {
        FAIL;
        return 0;
    }
    if (sz != strlen(buffer)) {
        FAIL;
        return 0;
    }

    return 1;
}

int
probe_result_attribute()
{
    char                 buffer[4096];
    char                 tmp[100];
    unsigned long        sz;
    int                  i;
    const int            test_count = 10;
    char *               p;
    enum mtf_test_result dummy_results[] = { TR_FAIL, TR_NONE, TR_PASS, TR_FAIL, TR_FAIL,
                                             TR_FAIL, TR_PASS, TR_PASS, TR_PASS, 3898 };
    char        dummy_result_chars[] = { 'f', '-', 'p', 'f', 'f', 'f', 'p', 'p', 'p', '!' };
    const char *dummy_names[] = { "bing",   "elvis",   "billy", "ella", "tony",
                                  "aretha", "maurice", "bobby", "kim",  "adele" };

    ___MTF_INNER_BEGIN_UTEST_COLLECTION_SHARED(toad, 0, 0);

    sz = inner_attr_show(&_mtf_toad_tci, "result", buffer);
    if (sz != 0) {
        FAIL;
        return 0;
    }

    _mtf_toad_tci.tci_state = ST_READY;
    sz = inner_attr_show(&_mtf_toad_tci, "result", buffer);
    if (sz != 0) {
        FAIL;
        return 0;
    }

    _mtf_toad_tci.tci_state = ST_RUNNING;
    sz = inner_attr_show(&_mtf_toad_tci, "result", buffer);
    if (sz != 0) {
        FAIL;
        return 0;
    }

    _mtf_toad_tci.tci_state = ST_ERROR;
    sz = inner_attr_show(&_mtf_toad_tci, "result", buffer);
    if (sz != 0) {
        FAIL;
        return 0;
    }

    _mtf_toad_tci.tci_state = ST_DONE;
    sz = inner_attr_show(&_mtf_toad_tci, "result", buffer);
    if (sz == 0) {
        FAIL;
        return 0;
    }
    if (memcmp(buffer, FINAL_SUCCESS, STATUS_CODE_LEN) != 0) {
        FAIL;
        return 0;
    }

    _mtf_toad_tci.tci_state = ST_DONE;
    _mtf_toad_tci.tci_num_tests = 1;
    _mtf_toad_tci.tci_test_names[0] = "passing";
    _mtf_toad_tci.tci_test_results[0] = TR_PASS;
    snprintf(tmp, sizeof(tmp), "%d\t%s\t%c", 0, "passing", 'p');
    sz = inner_attr_show(&_mtf_toad_tci, "result", buffer);
    if (sz == 0) {
        FAIL;
        return 0;
    }
    if (memcmp(buffer, FINAL_SUCCESS, STATUS_CODE_LEN) != 0) {
        FAIL;
        return 0;
    }
    p = strtok(buffer + STATUS_CODE_LEN, "\n");
    if (!p || strcmp(tmp, p) != 0) {
        FAIL;
        return 0;
    }

    _mtf_toad_tci.tci_state = ST_DONE;
    _mtf_toad_tci.tci_num_tests = test_count;
    for (i = 0; i < test_count; ++i) {
        _mtf_toad_tci.tci_test_results[i] = dummy_results[i];
        _mtf_toad_tci.tci_test_names[i] = dummy_names[i];
    }

    sz = inner_attr_show(&_mtf_toad_tci, "result", buffer);
    if (sz == 0) {
        FAIL;
        return 0;
    }
    if (memcmp(buffer, FINAL_SUCCESS, STATUS_CODE_LEN) != 0) {
        FAIL;
        return 0;
    }

    for (i = 0; i < test_count; ++i) {
        char tmp[100];
        snprintf(tmp, sizeof(tmp), "%d\t%s\t%c", i, dummy_names[i], dummy_result_chars[i]);
        if (i == 0)
            p = strtok(buffer + STATUS_CODE_LEN, "\n");
        else
            p = strtok(0, "\n");
        if (!p || strcmp(tmp, p) != 0) {
            FAIL;
            if (!p) {
                printf("p is NULL\n");
            } else {
                printf("p :%s:\n", p);
                printf("tmp :%s:\n", tmp);
            }
            return 0;
        }
    }

    return 1;
}

int
probe_large_result_attribute()
{
    char          buffer[4096];
    char          tmp[100];
    unsigned long sz;
    int           i;
    const int     test_count = 245;
    char *        p;
    char **       names;
    const int     NAME_LEN = 100;

    ___MTF_INNER_BEGIN_UTEST_COLLECTION_SHARED(toad, 0, 0);

    _mtf_toad_tci.tci_state = ST_DONE;
    _mtf_toad_tci.tci_num_tests = test_count;

    names = (char **)malloc(test_count * sizeof(char *));
    if (!names)
        return 0;
    for (i = 0; i < test_count; ++i) {
        names[i] = (char *)malloc(NAME_LEN + 1);
        if (!names[i])
            return 0; /* yes, this leaks ... */
    }

    for (i = 0; i < test_count; ++i) {
        enum mtf_test_result res = ((i % 3) == 0) ? TR_FAIL : TR_PASS;

        snprintf(names[i], NAME_LEN, "test_name%04d", i);
        _mtf_toad_tci.tci_test_results[i] = res;
        _mtf_toad_tci.tci_test_names[i] = names[i];
    }

    sz = inner_attr_show(&_mtf_toad_tci, "result", buffer);
    if (sz == 0) {
        FAIL;
        return 0;
    }
#if 0
    printf("buffer == :\n%s:\n", buffer);
#endif
    if (memcmp(buffer, PARTIAL_SUCCESS, STATUS_CODE_LEN) != 0) {
        FAIL;
        return 0;
    }

    i = 0;
    while (1) {
        char cres = ((i % 3) == 0) ? 'f' : 'p';

        snprintf(tmp, sizeof(tmp), "%d\ttest_name%04d\t%c", i, i, cres);
        if (i == 0)
            p = strtok(buffer + STATUS_CODE_LEN, "\n");
        else
            p = strtok(0, "\n");
        if (!p) {
            sz = inner_attr_show(&_mtf_toad_tci, "result", buffer);

            if (sz == 0) {
                FAIL;
                return 0;
            }
#if 0
            printf("buffer == :\n%s:\n", buffer);
#endif

            if (memcmp(buffer, FINAL_SUCCESS, STATUS_CODE_LEN) != 0) {
                FAIL;
                return 0;
            }
            p = strtok(buffer + STATUS_CODE_LEN, "\n");
        }
        if (strcmp(tmp, p) != 0) {
            FAIL;
            if (!p) {
                printf("p is NULL\n");
            } else {
                printf("p :%s:\n", p);
                printf("tmp :%s:\n", tmp);
            }
            return 0;
        }
        ++i;
        if (i == test_count)
            break;
    }

    for (i = 0; i < test_count; ++i) {
        free(names[i]);
    }
    free(names);

    return 1;
}

int
probe_output_attribute()
{
    char          buffer[4096];
    char          tmp[100];
    unsigned long sz;
    int           i;
    const int     test_count = 10;
    char *        p;

    ___MTF_INNER_BEGIN_UTEST_COLLECTION_SHARED(toad, 0, 0);

    _mtf_toad_tci.tci_outbuf = (char *)malloc(4096 * (1 << 4));
    if (!_mtf_toad_tci.tci_outbuf) {
        FAIL;
        return 0;
    }
    _mtf_toad_tci.tci_outbuf_len = 4096 * (1 << 4);

    sz = inner_mtf_print(&_mtf_toad_tci, "Output begin ...\n");
    for (i = 0; i < test_count; ++i) {
        inner_mtf_print(&_mtf_toad_tci, "sample data line %d\n", i);
    }
    sz = inner_mtf_print(&_mtf_toad_tci, "Output end\n");

    sz = inner_attr_show(&_mtf_toad_tci, "output", buffer);
    if (sz != 0) {
        FAIL;
        return 0;
    }

    _mtf_toad_tci.tci_state = ST_READY;
    sz = inner_attr_show(&_mtf_toad_tci, "output", buffer);
    if (sz != 0) {
        FAIL;
        return 0;
    }

    _mtf_toad_tci.tci_state = ST_RUNNING;
    sz = inner_attr_show(&_mtf_toad_tci, "output", buffer);
    if (sz != 0) {
        FAIL;
        return 0;
    }

    _mtf_toad_tci.tci_state = ST_ERROR;
    sz = inner_attr_show(&_mtf_toad_tci, "output", buffer);
    if (sz != 0) {
        FAIL;
        return 0;
    }

    _mtf_toad_tci.tci_state = ST_DONE;
    sz = inner_attr_show(&_mtf_toad_tci, "output", buffer);
    if (sz == 0) {
        FAIL;
        return 0;
    }
#if 0
    printf("buffer == :\n%s:\n", buffer);
#endif

    if (memcmp(buffer, FINAL_SUCCESS, STATUS_CODE_LEN) != 0) {
        FAIL;
        return 0;
    }
    p = strtok(buffer + STATUS_CODE_LEN, "\n");
    if (strcmp(p, "Output begin ...") != 0) {
        FAIL;
        return 0;
    }
    for (i = 0; i < test_count; ++i) {
        sprintf(tmp, "sample data line %d", i);
        p = strtok(0, "\n");
        if (strcmp(p, tmp) != 0) {
            FAIL;
            return 0;
        }
    }
    p = strtok(0, "\n");
    if (strcmp(p, "Output end") != 0) {
        FAIL;
        return 0;
    }

    free(_mtf_toad_tci.tci_outbuf);

    return 1;
}

int
probe_large_output_attribute()
{
    char          buffer[4096];
    char          tmp[100];
    unsigned long sz;
    int           i;
    const int     test_count = 435;
    char *        p = 0;
    int           final = 0;

    ___MTF_INNER_BEGIN_UTEST_COLLECTION_SHARED(toad, 0, 0);

    _mtf_toad_tci.tci_outbuf = (char *)malloc(4096 * (1 << 4));
    if (!_mtf_toad_tci.tci_outbuf) {
        FAIL;
        return 0;
    }
    _mtf_toad_tci.tci_outbuf_len = 4096 * (1 << 4);

    for (i = 0; i < test_count; ++i) {
        inner_mtf_print(&_mtf_toad_tci, "sample data line %d\n", i);
    }

    sz = inner_attr_show(&_mtf_toad_tci, "output", buffer);
    if (sz != 0) {
        FAIL;
        return 0;
    }

    _mtf_toad_tci.tci_state = ST_READY;
    sz = inner_attr_show(&_mtf_toad_tci, "output", buffer);
    if (sz != 0) {
        FAIL;
        return 0;
    }

    _mtf_toad_tci.tci_state = ST_RUNNING;
    sz = inner_attr_show(&_mtf_toad_tci, "output", buffer);
    if (sz != 0) {
        FAIL;
        return 0;
    }

    _mtf_toad_tci.tci_state = ST_ERROR;
    sz = inner_attr_show(&_mtf_toad_tci, "output", buffer);
    if (sz != 0) {
        FAIL;
        return 0;
    }

    _mtf_toad_tci.tci_state = ST_DONE;

    for (i = 0; i < test_count; ++i) {
        if (p == 0) {
            if (final) {
                FAIL;
                return 0;
            }
            sz = inner_attr_show(&_mtf_toad_tci, "output", buffer);
            if (sz == 0) {
                FAIL;
                return 0;
            }
            if (memcmp(buffer, FINAL_SUCCESS, STATUS_CODE_LEN) == 0) {
                final = 1;
            } else if (memcmp(buffer, PARTIAL_SUCCESS, STATUS_CODE_LEN) != 0) {
                FAIL;
                return 0;
            }
#if 0
            printf("buffer == :\n%s:\n", buffer);
#endif
            p = strtok(buffer + STATUS_CODE_LEN, "\n");
        }
        sprintf(tmp, "sample data line %d", i);
        if (strcmp(p, tmp) != 0) {
            FAIL;
            printf("p = :%s:    tmp = :%s:    i = %d\n", p, tmp, i);
            return 0;
        }
        p = strtok(0, "\n");
    }

    free(_mtf_toad_tci.tci_outbuf);

    return 1;
}

int
read_all_output_attribute()
{
    char          buffer[4096];
    unsigned long sz;
    int           i;
    char *        p = 0;
    int           final = 0;

    ___MTF_INNER_BEGIN_UTEST_COLLECTION_SHARED(toad, 0, 0);

    _mtf_toad_tci.tci_outbuf = (char *)malloc(4096 * (1 << 4));
    if (!_mtf_toad_tci.tci_outbuf) {
        FAIL;
        return 0;
    }
    _mtf_toad_tci.tci_outbuf_len = 4096 * (1 << 4);

    for (i = 0; i < 371; ++i) {
        inner_mtf_print(&_mtf_toad_tci, "sample data line %d\n", i);
    }

    _mtf_toad_tci.tci_state = ST_DONE;

    while (1) {
        if (p == 0) {
            if (final)
                break;
            sz = inner_attr_show(&_mtf_toad_tci, "output", buffer);
            if (sz == 0) {
                FAIL;
                return 0;
            }
            if (memcmp(buffer, FINAL_SUCCESS, STATUS_CODE_LEN) == 0) {
                final = 1;
            } else if (memcmp(buffer, PARTIAL_SUCCESS, STATUS_CODE_LEN) != 0) {
                FAIL;
                return 0;
            }
            p = strtok(buffer + STATUS_CODE_LEN, "\n");
        }
        p = strtok(0, "\n");
    }

    free(_mtf_toad_tci.tci_outbuf);

    return 1;
}

int
main(int argc, char *argv[])
{
    if (!instantiate_mtf_test_coll_info())
        return -1;

    if (!probe_status_attribute())
        return -1;

    if (!probe_result_attribute())
        return -1;

    if (!probe_large_result_attribute())
        return -1;

    if (!probe_output_attribute())
        return -1;

    if (!probe_large_output_attribute())
        return -1;

    if (!read_all_output_attribute())
        return -1;

    return 0;
}
