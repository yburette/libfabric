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
    struct mxr_fid_eq *eq_priv;

    eq_priv = container_of(fid, struct mxr_fid_eq, eq_fid.fid);

    fi_close((fid_t)eq_priv->util_eq);

#if 0 /*TODO: Needed? */

    if (eq_priv->domain) {
        fi_close((fid_t)&eq_priv->domain->util_domain.domain_fid.fid);
    }
#endif

    free(eq_priv);
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

#if 0
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
#endif

static ssize_t mxr_eq_sread(struct fid_eq *eq, uint32_t *event, void *buf,
        size_t len, int timeout, uint64_t flags)
{
    ssize_t nread;
    struct mxr_fid_eq *eq_priv;

    eq_priv = container_of(eq, struct mxr_fid_eq, eq_fid);

    /*TODO: Implement timeout */

    /* Check event list */
    /* if empty, CM Progress */
    /* Check event list again */

    nread = fi_eq_read(eq_priv->util_eq, event, buf, len, flags);
    if (-FI_EAGAIN != nread) {
        /* Either got an event or an error */
        return nread;
    }

    /* No event; let's progress CM */
    while (1) {
        nread = mxr_cm_progress(eq_priv->domain);
        if (nread > 0) {
            break;
        } else if (nread == 0) {
            if (timeout == 0) {
                break;
            }
            continue;
        } else {
            return nread;
        }
    }

    return fi_eq_read(eq_priv->util_eq, event, buf, len, flags);
}

static ssize_t mxr_eq_read(struct fid_eq *eq, uint32_t *event, void *buf,
        size_t len, uint64_t flags)
{
	return mxr_eq_sread(eq, event, buf, len, 0, flags);
}

static ssize_t mxr_eq_readerr(struct fid_eq *eq, struct fi_eq_err_entry *buf,
        uint64_t flags)
{
    struct mxr_fid_eq *eq_priv = container_of(eq, struct mxr_fid_eq, eq_fid);
    return fi_eq_readerr(eq_priv->util_eq, buf, flags);
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
    int ret;
    struct mxr_fid_eq *eq_priv;

    eq_priv = calloc(1, sizeof(struct mxr_fid_eq));
    if (!eq_priv) {
        return -FI_ENOMEM;
    }

    /* domain is missing at this point. Will defined when EQ is bound.
     * see mxr_ep_bind() and mxr_pep_bind() */
    ret = ofi_eq_create(fabric, attr, &eq_priv->util_eq, context);
    if (ret) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "ofi_eq_create failed: %d\n", ret);
        free(eq_priv);
        return ret;
    }
    eq_priv->domain = NULL;

    eq_priv->eq_fid.fid.fclass = FI_CLASS_EQ;
    eq_priv->eq_fid.fid.context = context;
    eq_priv->eq_fid.fid.ops = &mxr_fi_ops_eq;
    eq_priv->eq_fid.ops = &mxr_ops_eq;

    *eq = &eq_priv->eq_fid;

    return 0;
}
