/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2016 Micron Technology, Inc. All rights reserved.
 */

/*
 * wbtsize - wbt size calculator
 *
 * This program solves the space use calculations for a wbt
 * based upon a fixed key len (can be considered average).
 *
 * It reports number of leaves needed for a max sized kblock,
 * the number of interior nodes to support these leaves,
 * the number of pages of bloom to support them,
 * and various metrics of waste due to present (Oct 2016) omf.
 *
 * It also shows metrics if there are nleafs used.
 * And it calculates a unique factor: that number multiplied
 * by the key length that conservatively approximates the
 * number of internal nodes required.
 */

#include <getopt.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <hse/hse.h>

int level[12];
int nl, nkey, nblm, nie;
int nkpl, nkpi;
int max = 8191;

int
ie(int klen, int npages)
{
    int n;

    level[0] = npages;
    if (nkpi == 0)
        return nl = 1;
    n = 0;
    for (nl = 1; npages > 1; ++nl) {
        level[nl] = (npages + nkpi) / (nkpi + 1);
        npages = level[nl];
        n += level[nl];
    }
    return n;
}

int
solve(int klen, int doblm, int once)
{
    int t, nleaf;

    for (nleaf = once ?: max; nleaf > 1; nleaf--) {
        nkey = nleaf * nkpl;
        nblm = doblm * nkey * 11 / 8 / 4096;
        nie = ie(klen, nleaf);
        t = nleaf + nblm + nie;
        if (t < max || once)
            break;
    }

    return nleaf;
}

void
usage(char *prog)
{
    fprintf(stderr, "usage: %s [-bv] [-imMol n] keylen [valuelen]\n", prog);
    fprintf(
        stderr,
        "\t-i n\tforce the internal keys/internal to $n\n"
        "\t-m n\tset the max available kblock pages to $n\n"
        "\t-M n\tuse $n as max pages in vblock; default same as -m\n"
        "\t-o n\tuse $n as sizeof leaf_node_entry_omf\n"
        "\t-l n\tuse $n as number of leaves\n"
        "\t-b\tdisable bloom filters\n"
        "\t-v\tdump the wbt structure\n");
    exit(1);
}

int
main(int ac, char **av)
{
    char * prog;
    int    klen, vlen, nleaf, vmax;
    int    wleaf, wie, omf;
    int    blm, verbose;
    int    total, ohead;
    double wpct;
    int    c;

    nkpi = -1;
    blm = 1;
    verbose = 0;
    omf = 16;
    nleaf = 0;
    vmax = max;

    prog = basename(av[0]);
    while ((c = getopt(ac, av, "?i:m:M:o:l:bv")) != -1) {
        switch (c) {
            case 'i':
                nkpi = atoi(optarg);
                break;
            case 'm':
                max = atoi(optarg);
                break;
            case 'M':
                vmax = atoi(optarg);
                break;
            case 'o':
                omf = atoi(optarg);
                break;
            case 'l':
                nleaf = atoi(optarg);
                break;
            case 'b':
                blm = 0;
                break;
            case 'v':
                verbose = 1;
                break;
            case '?': /* fallthru */
            default:
                usage(prog);
        }
    }

    ac -= optind;
    av += optind;

    if (ac < 1)
        usage(prog);

    klen = atoi(av[0]);
    vlen = ac > 1 ? atoi(av[1]) : 0;

    nkpl = 4088 / (klen + omf);
    if (nkpi < 0)
        nkpi = 4082 / (klen + 6); /* always has a right node */

    wleaf = 4088 - nkpl * (klen + omf);
    wie = 4082 - nkpi * (klen + 6);

    if (nkpi == 0)
        wie = 0;

    /*
	 * solve both the max leaves possible
	 * in the bounded set of pages given,
	 * AND the corresponding interior node layout
	 *
	 * if nleaf given as input, directly
	 * calculate resulting kblock / wbt / bloom
	 */
    nleaf = solve(klen, blm, nleaf);

    total = nleaf + nie + nblm + 1; /* +1 for header */
    ohead = total * 4096 - nkey * klen;
    wpct = (double)(nleaf * wleaf + nie * wie) / ((nleaf + nie) * 4096);

    printf(
        "klen %d factor %.02f k/pg %d w/pg %d "
        "nkey %d leaf %d ie %d blm %d ohead%% %.1f\n",
        klen,
        (double)nie / klen,
        nkpl,
        wleaf,
        nkey,
        nleaf,
        nie,
        nblm,
        100.0 * ohead / (total * 4096.0));

    if (verbose) {
        /* also-ran values: not as useful (IMHO) as the previous set */
        printf(
            "d levels %d wleaf %d wie %d waste%% %.1f totpages %d\n",
            nl,
            wleaf,
            wie,
            wpct * 100,
            total);

        /* optional vblock report - space used */
        if (vlen) {
            int64_t vm = (vmax - 1) * 4096;
            int64_t vb = (int64_t)vlen * (int64_t)nkey;
            int64_t nv = vb / vm;

            if (vb > vm * nv)
                ++nv;
            printf("vlen %d  vpages %d  nv %ld\n", vlen, vmax, nv);
        }

        while (nl-- > 0)
            printf("\t%d: %d\n", nl, level[nl]);
    }

    return 0;
}
