This directory contains binary images of kblocks and vblocks which are used
by several unit tests.  The file naming scheme is:

    ${dataset}.${kblock_version}    // kblocks
    ${dataset}.${vblock_version}    // vblocks

Kblocks have a three part version identifier that consists of the kblock
header version number, the wbtree version number and the bloom version number.
For example, "kb3_w2_b3" identifies kblock header version 3, wbtree version 2
and bloom version 3.

Here's a rundown of the data files in this directory:

    Kblock and vblock with 100 keys, created with simple_client:

        simple_100a.kb3_w2_b3
        simple_100a.vb1

    Kblock and vblock with 100 keys, created with simple_client, updated for
    wbtree version 3:

        simple_100b.kb3_w3_b3
        simple_100b.vb1

    Kblock and vblock with 100 keys and 4 values per key, created with ctxn_validation:

        multival_100keys_4vals.kb3_w3_b3.xz
        multival_100keys_4vals.vb1.xz

    Kblock and vblock with 10 keys and 2000 values per key, created with ctxn_validation:

        multival_10keys_2000vals.kb3_w3_b3.xz
        multival_10keys_2000vals.vb1.xz


How to create new versions of these files
-----------------------------------------

The command line syntax for these tools may have changed from what is
documented here.  Use these instructions as a guide and update them
accordingly.

1. Create a new KVS and put 1031 keys

    hse kvdb create mp1/kvdb1
    hse kvs create mp1/kvdb1/kvs1
    simple_client mp1 kvdb1 kvs1 -c 1031 -v -f"key.%09d"

2. Dump the cn metadata log to see the kblock and vblock IDs:

    cn_metrics mp1 kvdb1 kvs1
    cn_kbdump mp1 kvdb1

Sample output:

    $  /opt/micron/bin/cn_metrics mp1 kvdb1 kvs1
    T Loc        Gen        NKeys       NTombs         KLen         VLen %Wst Comps  KB  VB Block IDs

    k 0,0,0        1         1031            0         4045         6660   99     0   1   1 0x00200108 / 0x00200105
    n 0,0,1        1         1031            0         4045         6660    0     0   1   1

    t 0,0,0        1         1031            0         4045         6660    0     0   1   1

    $ /opt/micron/bin/cn_kbdump  mp1 kvdb1 0x00200108 / 0x00200105
    0x00200105: V magic 0xea73feed  ver 2
    0x00200108: K magic 0xfadedfad  ver 5  nkey 1031  ntomb 0
        metrics: keys 1031 tombs 0 key_bytes 4045 val_bytes 6660
        wbt: hdr 112 24  data_pg 1 6
        pt: hdr 168 24  data_pg 0 0
        blm: hdr 136 32  data_pg 7 1
        kmd: start_pg 4
        keymin: off 2744 len 2 key k0
        keymax: off 1392 len 4 key k999
        blmhdr: magic 0x626c6d68  ver 4  bktsz 64  rotl 11  hashes 8  bitmapsz 4096  modulus 32749
        blm dist    min:   0.104 (53 / 512)
        blm dist    .3%:   0.104 (53 / 512)
        blm dist   2.1%:   0.141 (72 / 512)
        blm dist median:   0.217 (111 / 512)
        blm dist   mean:   0.219 (112 / 512)
        blm dist  97.9%:   0.330 (169 / 512)
        blm dist  99.7%:   0.334 (171 / 512)
        blm dist    max:   0.334 (171 / 512)
        blm bucket size:   64 (512 bits)
        wbthdr: magic 0x4a3a2a1a  ver 4  root 2  leaf1 0  nleaf 2 kmdpgc 3
    ptombs
        wbthdr: magic 0x4a3a2a1a  ver 4  root 0  leaf1 0  nleaf 0 kmdpgc 0


3. Extract mblocks from cn and save in files:

    # Note: do not need KVS name on command line
    cn_kbdump mp1 kvdb1 -w . mp1 0x00200108 / 0x00200105

The following files are created by cn_kbdump:

    K000.0x00100108.gz
    V000.0x00100105.gz

4. Rename and compress with xz:

    gunzip K0*.gz V0*.gz

    mv K0.0x00100108 simple_1031c.kbX_wY_bZ
    mv V0.0x00100105 simple_1031c.vb1

    xz simple_100c.kbX_wY_bZ simple_100c.vb1

4. Inspect files just for fun:

    cn_kbdump -K 30 -V 30  -r simple_1031c.*

5. Create multival kblocks:

    ctxn_validation -i 1000 -k 10  -K1024 mp1 db1 $kvs -ppc
    ctxn_validation -i 2    -k 100 -K1024 mp1 db1 $kvs -ppc

