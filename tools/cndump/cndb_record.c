/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#include "cndb/omf.h"
#include <hse/util/page.h>

#include "cndb_record.h"
#include "fatal.h"

const char *
cndb_rec_type_name(enum cndb_rec_type rtype)
{
    switch (rtype) {
    case CNDB_TYPE_VERSION:     return "version";
    case CNDB_TYPE_META:        return "meta";
    case CNDB_TYPE_TXSTART:     return "txstart";
    case CNDB_TYPE_KVS_ADD:     return "kvs_add";
    case CNDB_TYPE_KVS_DEL:     return "kvs_del";
    case CNDB_TYPE_KVSET_ADD:   return "kvset_add";
    case CNDB_TYPE_KVSET_DEL:   return "kvset_del";
    case CNDB_TYPE_KVSET_MOVE:  return "kvset_move";
    case CNDB_TYPE_ACK:         return "ack";
    case CNDB_TYPE_NAK:         return "nak";
    }
    return "unknown";
}

void
cndb_rec_init(struct cndb_rec *rec)
{
    memset(rec, 0, sizeof(*rec));
}

void
cndb_rec_resize(struct cndb_rec *rec, size_t reclen)
{
    size_t newsz = ALIGN(reclen, 16);
    void *p;

    if (newsz <= rec->bufsz)
        return;

    p = realloc(rec->buf, newsz);
    if (!p)
        fatal("realloc", merr(ENOMEM));

    rec->bufsz = newsz;
    rec->buf = p;
}

void
cndb_rec_clone(struct cndb_rec *rec, struct cndb_rec *clone)
{
    clone->len = rec->len;
    clone->type = rec->type;
    if (rec->bufsz) {
        clone->bufsz = rec->bufsz;
        clone->buf = malloc(rec->bufsz);
        if (!clone->buf)
            fatal("malloc", merr(ENOMEM));
        memcpy(clone->buf, rec->buf, rec->bufsz);
        cndb_rec_parse(clone);
    } else {
        clone->bufsz = 0;
        clone->buf = NULL;
    }
}

void
cndb_rec_fini(struct cndb_rec *rec)
{
    free(rec->buf);
}

void
cndb_rec_parse(struct cndb_rec *rec)
{
    memset(&rec->rec, 0, sizeof(rec->rec));

    switch (rec->type) {

    case CNDB_TYPE_VERSION: {
        struct cndb_rec_version *r = &rec->rec.version;
        cndb_omf_ver_read(rec->buf, &r->magic, &r->version, &r->size);
        break;
    }

    case CNDB_TYPE_META: {
        struct cndb_rec_meta *r = &rec->rec.meta;
        cndb_omf_meta_read(rec->buf, &r->seqno);
        break;
    }

    case CNDB_TYPE_KVS_ADD: {
        struct cndb_rec_kvs_add *r = &rec->rec.kvs_add;
        cndb_omf_kvs_add_read(rec->buf, &r->cp, &r->cnid, r->name, sizeof(r->name));
        break;
    }

    case CNDB_TYPE_KVS_DEL: {
        struct cndb_rec_kvs_del *r = &rec->rec.kvs_del;
        cndb_omf_kvs_del_read(rec->buf, &r->cnid);
        break;
    }

    case CNDB_TYPE_TXSTART: {
        struct cndb_rec_txstart *r = &rec->rec.txstart;
        cndb_omf_txstart_read(rec->buf, &r->txid, &r->seqno, &r->ingestid, &r->txhorizon,
            &r->add_cnt, &r->del_cnt);
        break;
    }

    case CNDB_TYPE_KVSET_ADD: {
        struct cndb_rec_kvset_add *r = &rec->rec.kvset_add;
        cndb_omf_kvset_add_read(rec->buf, &r->txid, &r->cnid, &r->kvsetid, &r->nodeid,
            &r->hblkid, &r->kblkc, &r->kblkv, &r->vblkc, &r->vblkv, &r->km);
        break;
    }

    case CNDB_TYPE_KVSET_DEL: {
        struct cndb_rec_kvset_del *r = &rec->rec.kvset_del;
        cndb_omf_kvset_del_read(rec->buf, &r->txid, &r->cnid, &r->kvsetid);
        break;
    }

    case CNDB_TYPE_KVSET_MOVE: {
        struct cndb_rec_kvset_move *r = &rec->rec.kvset_move;
        cndb_omf_kvset_move_read(rec->buf, &r->cnid, &r->src_nodeid, &r->tgt_nodeid,
            &r->kvset_idc, &r->kvset_idv);
        break;
    }

    case CNDB_TYPE_ACK: {
        struct cndb_rec_ack *r = &rec->rec.ack;
        cndb_omf_ack_read(rec->buf, &r->txid, &r->cnid, &r->ack_type, &r->kvsetid);
        break;
    }

    case CNDB_TYPE_NAK: {
        struct cndb_rec_nak *r = &rec->rec.nak;
        cndb_omf_nak_read(rec->buf, &r->txid);
            break;
        }
    }
}

static void
print_long_line_break(bool oneline, int indent)
{
    if (oneline)
        printf(" ");
    else
        printf("\n%*s ", indent, "");
}

void
cndb_rec_print(const struct cndb_rec *rec, bool oneline)
{
    const int indent = -12;
    const char *rec_type_name;
    size_t reclen;

    rec_type_name = cndb_rec_type_name(rec->type);
    reclen = rec->len;

    switch (rec->type) {

    case CNDB_TYPE_VERSION: {
        const struct cndb_rec_version *r = &rec->rec.version;
        printf("%*s version %u magic 0x%x size %lu reclen %zu\n",
            indent, rec_type_name, r->version, r->magic, r->size, reclen);
        break;
    }

    case CNDB_TYPE_META: {
        const struct cndb_rec_meta *r = &rec->rec.meta;
        printf("%*s seqno %lu reclen %zu\n", indent, rec_type_name, r->seqno, reclen);
        break;
    }

    case CNDB_TYPE_KVS_ADD: {
        const struct cndb_rec_kvs_add *r = &rec->rec.kvs_add;
        printf("%*s name %s cnid %lu pfxlen %u capped %c reclen %zu\n",
            indent, rec_type_name, r->name, r->cnid, r->cp.pfx_len,
            r->cp.kvs_ext01 ? 'y' : 'n', reclen);
        break;
    }

    case CNDB_TYPE_KVS_DEL: {
        const struct cndb_rec_kvs_del *r = &rec->rec.kvs_del;
        printf("%*s cnid %lu reclen %zu\n", indent, rec_type_name, r->cnid, reclen);
        break;
    }

    case CNDB_TYPE_TXSTART: {
        const struct cndb_rec_txstart *r = &rec->rec.txstart;
        printf("%*s txid %lu seqno %lu ingestid %lu txhorizon %lu add %u del %u reclen %zu\n",
            indent, rec_type_name, r->txid, r->seqno, r->ingestid,
            r->txhorizon, r->add_cnt, r->del_cnt, reclen);
        break;
    }

    case CNDB_TYPE_KVSET_ADD: {

        const struct cndb_rec_kvset_add *r = &rec->rec.kvset_add;

        printf("%*s txid %lu cnid %lu kvsetid %lu nodeid %lu dgen_hi %lu dgen_lo %lu "
            "vused %lu compc %u reclen %zu",
            indent, rec_type_name, r->txid, r->cnid, r->kvsetid, r->nodeid,
            r->km.km_dgen_hi, r->km.km_dgen_lo, r->km.km_vused, r->km.km_compc, reclen);

        print_long_line_break(oneline, indent);
        printf("hblock 0x%lx", r->hblkid);

        print_long_line_break(oneline, indent);
        printf("kblocks %u", r->kblkc);
        for (int i = 0; i < r->kblkc; i++)
            printf(" 0x%lx", r->kblkv[i]);

        print_long_line_break(oneline, indent);
        printf("vblocks %u", r->vblkc);
        for (int i = 0; i < r->vblkc; i++)
            printf(" 0x%lx", r->vblkv[i]);

        printf("\n");
        break;
    }

    case CNDB_TYPE_KVSET_DEL: {
        const struct cndb_rec_kvset_del *r = &rec->rec.kvset_del;
        printf("%*s txid %lu cnid %lu kvsetid %lu reclen %zu\n",
            indent, rec_type_name, r->txid, r->cnid, r->kvsetid, reclen);
        break;
    }

    case CNDB_TYPE_KVSET_MOVE: {
        const struct cndb_rec_kvset_move *r = &rec->rec.kvset_move;
        printf("%*s cnid %lu src_nodeid %lu tgt_nodeid %lu reclen %zu",
            indent, rec_type_name, r->cnid, r->src_nodeid, r->tgt_nodeid, reclen);
        print_long_line_break(oneline, indent);
        printf("kvsets %u", r->kvset_idc);
        for (uint32_t i = 0; i < r->kvset_idc; i++)
            printf(" %lu", r->kvset_idv[i]);
        printf("\n");
        break;
    }

    case CNDB_TYPE_ACK: {
        const struct cndb_rec_ack *r = &rec->rec.ack;
        char modified_name[32];
        snprintf(modified_name, sizeof(modified_name), "%s%s",
            rec_type_name, r->ack_type == CNDB_ACK_TYPE_ADD ? "_add" : "_del");
        printf("%*s txid %lu cnid %lu kvsetid %lu reclen %zu\n",
            indent, modified_name, r->txid, r->cnid, r->kvsetid, reclen);
        break;
    }

    case CNDB_TYPE_NAK: {
        const struct cndb_rec_nak *r = &rec->rec.nak;
        printf("%*s txid %lu reclen %zu\n", indent, rec_type_name, r->txid, reclen);
        break;
    }
    }
}
