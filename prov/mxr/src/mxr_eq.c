/*
 * Copyright (c) 2016 Intel Corporation, Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "mxr.h"

static int mxr_eq_close(fid_t fid)
{
    int ret;
    struct mxr_fid_eq *mxr_eq = container_of(fid, struct mxr_fid_eq, eq.fid);

    if (mxr_eq->rd_cq) {
        ret = fi_close((fid_t)mxr_eq->rd_cq);
        if (ret)
            return ret;
    }

    if (mxr_eq->error_conn_buf) {
        free(mxr_eq->error_conn_buf);
    }

    free(mxr_eq);
    return 0;
}

static int mxr_eq_control(struct fid *fid, int command, void *arg)
{
    return -FI_ENOSYS;
}

struct fi_ops mxr_fi_ops_eq = {
    .size = sizeof(struct fi_ops),
    .close = mxr_eq_close,
    .bind = fi_no_bind,
    .control = mxr_eq_control,
    .ops_open = fi_no_ops_open
};

int process_connresp(struct mxr_conn_buf *buf, size_t datalen)
{
    int ret;
    char *name;
    size_t count;
    size_t namelen;
    size_t len;
    struct mxr_conn_buf ack;
    struct mxr_fid_ep *mxr_ep = buf->mxr_ep;

    namelen = (datalen - sizeof(struct mxr_conn_hdr)) / 2;

    name = buf->data.epnames;
    count = fi_av_insert(mxr_ep->mxr_domain->rd_av, name, 1,
                         &mxr_ep->peer_ctrl_addr, 0, NULL);
    if (1 != count) {
        return -FI_EOTHER;
    }

    print_address("connresp peer_ctrl_addr:", name);

    name += namelen;
    count = fi_av_insert(mxr_ep->mxr_domain->rd_av, name, 1,
                         &mxr_ep->peer_data_addr, 0, NULL);
    if (1 != count) {
        return -FI_EOTHER;
    }

    print_address("connresp peer_data_addr:", name);

    ret = prepare_cm_req(&ack, MXR_CONN_ACK, mxr_ep, &buf->data.hdr.cm_data,
                         buf->data.hdr.cm_datalen, &len);
    if (ret) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "prepare_cm_req failed\n");
        goto freeack;
    }

    ret = fi_send(mxr_ep->ctrl_ep, &ack.data.hdr, len, NULL,
                  mxr_ep->peer_ctrl_addr, (void *) &ack.ctx);

freeack:
    /* TODO: free ack */
    return ret;
}

int process_connrej(struct mxr_conn_buf *buf, size_t len, struct mxr_fid_eq *eq)
{
    struct fi_eq_err_entry *error = &eq->error;
    error->fid = &buf->mxr_ep->ep.fid;
    error->context = NULL;
    error->data = 0;
    error->err = FI_ECONNREFUSED;
    error->prov_errno = 0;
    error->err_data = &buf->data.hdr.cm_data;
    error->err_data_size = buf->data.hdr.cm_datalen;
    if (eq->error_conn_buf) {
        /* Free previous error */
        free(eq->error_conn_buf);
    }
    eq->error_conn_buf = buf;

    return 0;
}

static ssize_t mxr_eq_sread(struct fid_eq *eq, uint32_t *event, void *buf,
        size_t len, int timeout, uint64_t flags)
{
    int ret;
    struct mxr_fid_ep *mxr_ep;
    struct mxr_fid_eq *mxr_eq = container_of(eq, struct mxr_fid_eq, eq);
    struct fid_cq *rd_cq = mxr_eq->rd_cq;
    struct fi_cq_tagged_entry wc = { 0 };
    struct mxr_conn_buf* conn_buf = NULL;
    struct fi_eq_cm_entry *entry = (struct fi_eq_cm_entry*)buf;
    size_t nameslen;
    struct fi_info *info;
    ssize_t count = 0;

    /* TODO: implement timeout */
    while (1) {
        if (mxr_eq->shutdown_entry) {
            /* An EP was shut down */
            *event = FI_SHUTDOWN;
            entry->fid = mxr_eq->shutdown_entry->fid;
            count = sizeof(*entry);
            free(mxr_eq->shutdown_entry);
            mxr_eq->shutdown_entry = NULL;
            break;
        }
        ret = fi_cq_read(rd_cq, (void*)&wc, 1);
        if (ret > 0) {
            FI_INFO(&mxr_prov, FI_LOG_FABRIC, "EQ completion 0x%x\n", wc.flags);
            conn_buf = TO_MXR_CONN_BUF(wc.op_context);
            if (wc.flags & FI_SEND) {
                free(conn_buf);
                continue;
            }
            switch(conn_buf->data.hdr.type) {
            case MXR_CONN_REQ:
                FI_INFO(&mxr_prov, FI_LOG_FABRIC, "Got a MXR_CONN_REQ!\n");
                nameslen = wc.len - sizeof(struct mxr_conn_hdr);
                FI_INFO(&mxr_prov, FI_LOG_FABRIC, "nameslen: %ld\n", nameslen);
                /* TODO: verify namelen is the same as ours (pep?) */
                info = fi_dupinfo(mxr_eq->mxr_pep->info);
                if (!info) {
                    return -FI_ENOMEM;
                }
                /* TODO: is info->dest_addr already allocated? */
                info->dest_addr = calloc(nameslen, sizeof(char));
                if (!info->dest_addr) {
                    return -FI_ENOMEM;
                }
                memcpy(info->dest_addr, conn_buf->data.epnames, nameslen);
                info->dest_addrlen = nameslen;
                /* info will be used by fi_reject(). See mxr_cm.c */
                info->handle = (fid_t)info;
                *event = FI_CONNREQ;
                if (conn_buf->data.hdr.cm_datalen > 0) {
                    memcpy(entry->data, &conn_buf->data.hdr.cm_data,
                           conn_buf->data.hdr.cm_datalen);
                }
                entry->info = info;
                count = sizeof(*entry) + conn_buf->data.hdr.cm_datalen;
                /* Re-post recv buffer */
                ret = fi_recv(mxr_eq->mxr_pep->ctrl_ep, 
                              &conn_buf->data,
                              sizeof(struct mxr_conn_pkt),
                              NULL,
                              FI_ADDR_UNSPEC,
                              (void *) &conn_buf->ctx);
                if (ret) {
                    FI_WARN(&mxr_prov, FI_LOG_FABRIC,
                            "Couldn't re-post connreq buffer\n", ret);
                    return -FI_EOTHER;
                }
                break;
            case MXR_CONN_RESP:
                FI_INFO(&mxr_prov, FI_LOG_FABRIC, "Got a MXR_CONN_RESP!\n");
                ret = process_connresp(conn_buf, wc.len);
                if (ret) {
                    FI_WARN(&mxr_prov, FI_LOG_FABRIC,
                            "Couldn't process connection response: %d\n", ret);
                    return -FI_EOTHER;
                }
                *event = FI_CONNECTED;
                mxr_ep = conn_buf->mxr_ep;
                mxr_ep->connected = 1;
                entry->fid = &mxr_ep->ep.fid;
                if (conn_buf->data.hdr.cm_datalen > 0) {
                    memcpy(entry->data, &conn_buf->data.hdr.cm_data,
                           conn_buf->data.hdr.cm_datalen);
                }
                count = sizeof(*entry) + conn_buf->data.hdr.cm_datalen;
                free(conn_buf);
                break;
            case MXR_CONN_ACK:
                FI_INFO(&mxr_prov, FI_LOG_FABRIC, "Got a MXR_CONN_ACK!\n");
                *event = FI_CONNECTED;
                mxr_ep = conn_buf->mxr_ep;
                mxr_ep->connected = 1;
                entry->fid = &mxr_ep->ep.fid;
#if 0
                /* Client-side gets cm_data if present */
                if (conn_buf->data.hdr.cm_datalen > 0) {
                    memcpy(entry->data, &conn_buf->data.hdr.cm_data,
                           conn_buf->data.hdr.cm_datalen);
                }
                count = sizeof(*entry) + conn_buf->data.hdr.cm_datalen;
#endif
                count = sizeof(*entry);
                free(conn_buf);
                break;
            case MXR_CONN_REJ:
                FI_INFO(&mxr_prov, FI_LOG_FABRIC, "Got a MXR_CONN_REJ!\n");
                ret = process_connrej(conn_buf, wc.len, mxr_eq);
                if (ret) {
                    FI_WARN(&mxr_prov, FI_LOG_FABRIC,
                            "Couldn't process connection reject: %d\n", ret);
                    return -FI_EOTHER;
                }
                return -FI_EAVAIL;
            default:
                FI_WARN(&mxr_prov, FI_LOG_FABRIC,
                        "Unknown type: %d\n", conn_buf->data.hdr.type);
                return -FI_EOTHER;
            }
            break;
        } else if (-FI_EAGAIN == ret) {
            if (timeout == 0) {
                return ret;
            }
            continue;
        } else if (-FI_EAVAIL == ret) {
            /* TODO: Retrieve error? */
            FI_WARN(&mxr_prov, FI_LOG_FABRIC,
                    "fi_cq_read returned an error\n");
            return -FI_EOTHER;
        }
    }
    return count;
}

static ssize_t mxr_eq_read(struct fid_eq *eq, uint32_t *event, void *buf,
        size_t len, uint64_t flags)
{
	return mxr_eq_sread(eq, event, buf, len, 0, flags);
}

static ssize_t mxr_eq_readerr(struct fid_eq *eq, struct fi_eq_err_entry *buf,
        uint64_t flags)
{
    struct mxr_fid_eq *mxr_eq = container_of(eq, struct mxr_fid_eq, eq);
    memcpy(buf, &mxr_eq->error, sizeof(struct fi_eq_err_entry));

    return sizeof(struct fi_eq_err_entry);
}

static ssize_t mxr_eq_write(struct fid_eq *eq, uint32_t event,
        const void *buf, size_t len, uint64_t flags)
{
    return -FI_ENOSYS;
}

static const char *mxr_eq_strerror(struct fid_eq *eq, int prov_errno,
        const void *err_data, char *buf, size_t len)
{
    return NULL;
}

struct fi_ops_eq mxr_ops_eq = {
    .size = sizeof(struct fi_ops_eq),
    .read = mxr_eq_read,
    .readerr = mxr_eq_readerr,
    .write = mxr_eq_write,
    .sread = mxr_eq_sread,
    .strerror = mxr_eq_strerror
};

int mxr_eq_open(struct fid_fabric *fabric, struct fi_eq_attr *attr,
        struct fid_eq **eq, void *context)
{
    struct mxr_fid_eq *mxr_eq;

    mxr_eq = calloc(1, sizeof(struct mxr_fid_eq));
    if (!mxr_eq) {
        return -FI_ENOMEM;
    }

    /* rd_domain is missing at this point, so CQ is created
     * when EQ is bound to (P)EP. See mxr_pep_bind() and mxr_ep_bind(). */

    mxr_eq->cq_attr.format = FI_CQ_FORMAT_TAGGED;
    /* Save attributes into CQ attributes */
    /*TODO: what about other fields? */
    mxr_eq->cq_attr.size = attr->size;
    mxr_eq->cq_attr.wait_obj = attr->wait_obj;

    mxr_eq->eq.fid.fclass = FI_CLASS_EQ;
    mxr_eq->eq.fid.context = context;
    mxr_eq->eq.fid.ops = &mxr_fi_ops_eq;
    mxr_eq->eq.ops = &mxr_ops_eq;

    slist_init(&mxr_eq->connreqs);

    *eq = &mxr_eq->eq;

    return 0;
}
