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

#include <stdlib.h>
#include <string.h>

#include "mxr.h"


static int mxr_trywait(struct fid_fabric *fabric, struct fid **fids, int count)
{
    /*TODO: What should we do here? */
    struct mxr_fid_fabric *mxr_fabric;
    struct mxr_fid_cq *mxr_cq;
	int i, ret;
    struct fid *rd_fids[1];

    mxr_fabric = container_of(fabric, struct mxr_fid_fabric, util_fabric.fabric_fid);
	for (i = 0; i < count; i++) {
		switch (fids[i]->fclass) {
			case FI_CLASS_CQ:
                mxr_cq = container_of(fids[i], struct mxr_fid_cq, cq);
                rd_fids[0] = &mxr_cq->rd_cq->fid;
                ret = fi_trywait(mxr_fabric->rd_fabric, rd_fids, 1);
                if (ret) {
                    return ret;
                }
                break;
           default:
                FI_WARN(&mxr_prov, FI_LOG_FABRIC, "Unknown fid class: %d\n",
                        fids[i]->fclass);
                return -FI_EINVAL;
        }
    }
    return FI_SUCCESS;
}

static struct fi_ops_fabric mxr_fabric_ops = {
    .size = sizeof(struct fi_ops_fabric),
    .domain = mxr_domain_open,
    .passive_ep = mxr_passive_ep,
    .eq_open = mxr_eq_open,
    .wait_open = ofi_wait_fd_open,
    .trywait = mxr_trywait
};

static int mxr_fabric_close(fid_t fid)
{
    int ret;
    struct mxr_fid_fabric *mxr_fabric = container_of(fid,
                                                     struct mxr_fid_fabric,
                                                     util_fabric.fabric_fid);

    FI_WARN(&mxr_prov, FI_LOG_FABRIC,
            "closing mxr_fabric %p rd_fabric %p refcnt=%d\n",
            mxr_fabric, mxr_fabric->rd_fabric, mxr_fabric->refcnt);

    if (mxr_fabric != mxr_active_fabric) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "mxr_fabric != mxr_active_fabric\n");
        return -FI_EINVAL;
    }

    mxr_fabric->refcnt--;

    if (mxr_fabric->refcnt != 0) {
        return 0;
    }

    if (mxr_fabric->domain) {
        fi_close((fid_t)mxr_fabric->domain);
    }

    ret = fi_close((fid_t)mxr_fabric->rd_fabric);
    if (ret)
        return ret;

    ret = ofi_fabric_close(&mxr_fabric->util_fabric);
    if (ret)
        return ret;

    free(mxr_fabric);
    return 0;
}

static struct fi_ops mxr_fabric_fi_ops = {
    .size = sizeof(struct fi_ops),
    .close = mxr_fabric_close,
    .bind = fi_no_bind,
    .control = fi_no_control,
    .ops_open = fi_no_ops_open
};

int mxr_fabric(struct fi_fabric_attr *attr, struct fid_fabric **fabric,
        void *context)
{
    int ret;
    struct mxr_fid_fabric *mxr_fabric = NULL;
    struct fi_info *hints;
    struct fi_info *rd_info;

    if (mxr_active_fabric) {
        mxr_active_fabric->refcnt++;
        *fabric = &mxr_active_fabric->util_fabric.fabric_fid;
        return 0;
    }

    mxr_fabric = calloc(1, sizeof(struct mxr_fid_fabric));
    if (!mxr_fabric) {
        return -FI_ENOMEM;
    }

	ret = ofi_fabric_init(&mxr_prov, &mxr_fabric_attr, attr,
			              &mxr_fabric->util_fabric, context, FI_MATCH_PREFIX);
    if (ret) {
        goto freefabric;
    }

    hints = fi_allocinfo();
    if (!hints) {
        ret = -FI_ENOMEM;
        goto closefabric;
    }
    hints->fabric_attr->name = strdup(attr->name);
    hints->domain_attr->mr_mode = mxr_info.domain_attr->mr_mode;

    ret = ofix_getinfo(mxr_prov.version, NULL, NULL, 0, &mxr_util_prov, hints,
                       mxr_alter_layer_info, mxr_alter_base_info, 1, &rd_info);
    if (ret) {
        goto freehints;
    }

    ret = fi_fabric(rd_info->fabric_attr, &mxr_fabric->rd_fabric, context);
    if (ret) {
        goto freeinfo;
    }

    mxr_cm_init();

    mxr_fabric->rd_info = rd_info;
    mxr_fabric->domain = NULL; /* To be initialized by pep or domain */
    mxr_fabric->refcnt = 1;

    FI_INFO(&mxr_prov, FI_LOG_FABRIC,
            "new mxr_fabric %p rd_fabric %p\n",
            mxr_fabric, mxr_fabric->rd_fabric);

    *fabric = &mxr_fabric->util_fabric.fabric_fid;
    (*fabric)->fid.ops = &mxr_fabric_fi_ops;
    (*fabric)->ops = &mxr_fabric_ops;

    mxr_active_fabric = mxr_fabric;

    fi_freeinfo(hints);
    return 0;
freeinfo:
    fi_freeinfo(rd_info);
freehints:
    fi_freeinfo(hints);
closefabric:
    ofi_fabric_close(&mxr_fabric->util_fabric);
freefabric:
    free(mxr_fabric);
    return ret;
}
