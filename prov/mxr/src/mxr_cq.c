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

static int mxr_cq_close(fid_t fid)
{
    int ret;
    struct mxr_fid_cq *mxr_cq = container_of(fid, struct mxr_fid_cq, cq.fid);

    if (mxr_cq->rd_cq) {
        ret = fi_close((fid_t)mxr_cq->rd_cq);
        if (ret)
            return ret;
    }

    free(mxr_cq);
    return 0;
}

static int mxr_cq_control(struct fid *fid, int command, void *arg)
{
    struct mxr_fid_cq *cq = container_of(fid, struct mxr_fid_cq, cq.fid);
    return fi_control((fid_t)cq->rd_cq, command, arg);
}

struct fi_ops mxr_fi_ops_cq = {
    .size = sizeof(struct fi_ops),
    .close = mxr_cq_close,
    .bind = fi_no_bind,
    .control = mxr_cq_control,
    .ops_open = fi_no_ops_open
};

static ssize_t mxr_cq_read(struct fid_cq *cq, void *buf, size_t count)
{
    ssize_t nread;
    struct fi_cq_entry *entry;
    size_t entry_size;
    size_t i;
    struct mxr_request *mxr_req;
    struct mxr_fid_cq *mxr_cq = container_of(cq, struct mxr_fid_cq, cq.fid);

    switch(mxr_cq->format) {
    case FI_CQ_FORMAT_CONTEXT:
        entry_size = sizeof(struct fi_cq_entry);
        break;
    case FI_CQ_FORMAT_MSG:
        entry_size = sizeof(struct fi_cq_msg_entry);
        break;
	case FI_CQ_FORMAT_DATA:
        entry_size = sizeof(struct fi_cq_data_entry);
        break;
	case FI_CQ_FORMAT_TAGGED:
        entry_size = sizeof(struct fi_cq_tagged_entry);
        break;
    default:
        FI_WARN(&mxr_prov, FI_LOG_FABRIC,
                "Unknown CQ entry format: %d\n", mxr_cq->format);
        return -FI_EINVAL;
    }

    nread = fi_cq_read(mxr_cq->rd_cq, buf, count);
    if (nread < 0) {
        return nread;
    }

    /* Update the entries with the actual user_ptr */
    entry = buf;
    for(i = 0; i < nread; ++i) {
        if (entry->op_context) {
            mxr_req = TO_MXR_REQ(entry->op_context);
            entry->op_context = mxr_req->user_ptr;
#if 0 /* TODO: this causes some issues, why? */
            dlist_remove(&mxr_req->list_entry);
            free(mxr_req);
#endif
        }
        entry += entry_size;
    }

    return nread;
}

static ssize_t mxr_cq_readfrom(struct fid_cq *cq, void *buf, size_t count,
        fi_addr_t *src_addr)
{
    return -FI_ENOSYS;
}

static ssize_t mxr_cq_readerr(struct fid_cq *cq, struct fi_cq_err_entry *buf,
        uint64_t flags)
{
    ssize_t ret;
    struct fi_cq_err_entry *error;
    struct mxr_request *mxr_req;
    struct mxr_fid_cq *mxr_cq = container_of(cq, struct mxr_fid_cq, cq.fid);

    ret = fi_cq_readerr(mxr_cq->rd_cq, buf, flags);
    if (ret < 0) {
        return ret;
    }

    error = buf;
    mxr_req = TO_MXR_REQ(error->op_context);
    error->op_context = mxr_req->user_ptr;
    dlist_remove(&mxr_req->list_entry);
    free(mxr_req);

    return ret;
}

static ssize_t	mxr_cq_sread(struct fid_cq *cq, void *buf, size_t count,
        const void *cond, int timeout)
{
    return -FI_ENOSYS;
}

static ssize_t mxr_cq_sreadfrom(struct fid_cq *cq, void *buf, size_t count,
        fi_addr_t *src_addr, const void *cond, int timeout)
{
    return -FI_ENOSYS;
}

static int mxr_cq_signal(struct fid_cq *cq)
{
    return -FI_ENOSYS;
}

static const char *mxr_cq_strerror(struct fid_cq *cq, int prov_errno,
        const void *err_data, char *buf, size_t len)
{
    struct mxr_fid_cq *mxr_cq = container_of(cq, struct mxr_fid_cq, cq.fid);
    return fi_cq_strerror(mxr_cq->rd_cq, prov_errno, err_data, buf, len);
}

struct fi_ops_cq mxr_ops_cq = {
    .size = sizeof(struct fi_ops_cq),
    .read = mxr_cq_read,
    .readfrom = mxr_cq_readfrom,
    .readerr = mxr_cq_readerr,
    .sread = mxr_cq_sread,
    .sreadfrom = mxr_cq_sreadfrom,
    .signal = mxr_cq_signal,
    .strerror = mxr_cq_strerror
};

int mxr_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr,
        struct fid_cq **cq, void *context)
{
    int ret;
    struct mxr_fid_cq *mxr_cq;
    struct mxr_fid_domain *mxr_domain;

    mxr_domain = container_of(domain, struct mxr_fid_domain,
            util_domain.domain_fid);

    mxr_cq = calloc(1, sizeof(struct mxr_fid_cq));
    if (!mxr_cq) {
        return -FI_ENOMEM;
    }

    ret = fi_cq_open(mxr_domain->rd_domain, attr, &mxr_cq->rd_cq, context);
    if (ret) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "Cannot open CQ: %d\n", ret);
        goto freecq;
    }

    mxr_cq->cq.fid.fclass = FI_CLASS_CQ;
    mxr_cq->cq.fid.context = context;
    mxr_cq->cq.fid.ops = &mxr_fi_ops_cq;
    mxr_cq->cq.ops = &mxr_ops_cq;

    mxr_cq->format = attr->format;

    *cq = &mxr_cq->cq;

    return 0;
freecq:
    free(mxr_cq);
    return ret;
}
