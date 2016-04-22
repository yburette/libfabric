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
    return -FI_ENOSYS;
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

static ssize_t mxr_eq_sread(struct fid_eq *eq, uint32_t *event, void *buf,
        size_t len, int timeout, uint64_t flags)
{
    int ret;
    struct mxr_fid_eq *mxr_eq = (struct mxr_fid_eq*)eq;
    struct fid_cq *rd_cq = mxr_eq->rd_cq;
    struct fi_cq_tagged_entry wc = { 0 };
    struct fi_cq_err_entry error = { 0 };
    struct mxr_conn_buf* conn_buf = NULL;
    struct fi_eq_cm_entry *entry = (struct fi_eq_cm_entry*)buf;
    size_t namelen;
    struct fi_info *info;
    ssize_t count = 0;

    /* TODO: implement timeout */
    while (1) {
        ret = fi_cq_read(rd_cq, (void*)&wc, 1);
        if (ret > 0) {
            conn_buf = TO_MXR_CONN_BUF(wc.op_context);
            switch(conn_buf->data.hdr.type) {
            case ofi_ctrl_connreq:
                FI_WARN(&mxr_prov, FI_LOG_FABRIC, "Got a ofi_ctrl_connreq!\n");
                *event = FI_CONNREQ;
                namelen = wc.len - sizeof(struct ofi_ctrl_hdr);
                /* TODO: verify namelen is the same as ours (pep?) */
                info = mxr_eq->pep->info;
                /* TODO: is info->dest_addr already allocated? */
                info->dest_addr = calloc(namelen, sizeof(char));
                if (!info->dest_addr) {
                    return -FI_ENOMEM;
                }
                memcpy(info->dest_addr, conn_buf->data.addr, namelen);
                info->dest_addrlen = namelen;
                info->handle = (fid_t)mxr_eq->pep;
                FI_WARN(&mxr_prov, FI_LOG_FABRIC,
                        "info->handle %p\n", info->handle);
                entry->info = info;
                free(conn_buf);
                count = sizeof(*entry);
                break;
            case ofi_ctrl_connresp:
                FI_WARN(&mxr_prov, FI_LOG_FABRIC, "Got a ofi_ctrl_connresp!\n");
                break;
            default:
                /* TODO: Print error msg and bail */
                FI_WARN(&mxr_prov, FI_LOG_FABRIC,
                        "Unknown type: %d\n", conn_buf->data.hdr.type);
                return -FI_EOTHER;
            }
            break;
        } else if (-FI_EAGAIN == ret) {
            continue;
        } else if (-FI_EAVAIL == ret) {
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
    return -FI_ENOSYS;
}

static ssize_t mxr_eq_write(struct fid_eq *eq, uint32_t event,
        const void *buf, size_t len, uint64_t flags)
{
    return -FI_ENOSYS;
}

static const char *mxr_eq_strerror(struct fid_eq *eq, int prov_errno,
        const void *err_data, char *buf, size_t len)
{
    return -FI_ENOSYS;
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
     * when EQ is bound to (P)EP. See mxr_pep_bind(). */

    mxr_eq->eq.fid.fclass = FI_CLASS_EQ;
    mxr_eq->eq.ops = &mxr_ops_eq;

    *eq = mxr_eq;

    return 0;
}
