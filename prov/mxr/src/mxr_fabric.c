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

static struct fi_ops_fabric mxr_fabric_ops = {
    .size = sizeof(struct fi_ops_fabric),
    .domain = mxr_domain_open,
    .passive_ep = mxr_passive_ep,
    .eq_open = mxr_eq_open,
    .wait_open = ofi_wait_fd_open,
    .trywait = fi_no_trywait
};

static int mxr_fabric_close(fid_t fid)
{
    struct util_fabric *fabric;
    int ret;

    fabric = container_of(fid, struct util_fabric, fabric_fid.fid);
    ret = ofi_fabric_close(fabric);
    if (ret) {
        return ret;
    }
    free(fabric);
    return 0;
}

static struct fi_ops mxr_fabric_fi_ops = {
    .size = sizeof(struct fi_ops),
    .close = mxr_fabric_close,
    .bind = fi_no_bind,
    .control = fi_no_control,
    .ops_open = fi_no_ops_open
};

int mxr_fabric_open(struct fi_fabric_attr *attr, struct fid_fabric **fabric,
        void *context)
{
    int ret;
    struct mxr_fid_fabric *mxr_fabric = NULL;
    struct util_fabric *util_fabric = NULL;
    struct fi_info hints;
    struct fi_info *rd_info;

    mxr_fabric = calloc(1, sizeof(struct mxr_fid_fabric));
    if (!mxr_fabric) {
        return -FI_ENOMEM;
    }

	ret = ofi_fabric_init(&mxr_prov, &mxr_fabric_attr, attr,
			              &mxr_fabric->util_fabric, context, FI_MATCH_PREFIX);
    if (ret) {
        goto freefabric;
    }

    memset(&hints, 0, sizeof hints);
    hints.fabric_attr = calloc(1, sizeof(struct fi_fabric_attr));
    if (!hints.fabric_attr) {
        ret = -FI_ENOMEM;
        goto closefabric;
    }
    hints.fabric_attr->name = attr->name;

    ret = ofi_layered_prov_getinfo(mxr_prov.version, NULL, NULL, 0, &mxr_prov,
                                   &mxr_info, &hints, mxr_alter_layer_info,
                                   mxr_alter_base_info, 1, &rd_info);
    if (ret) {
        goto freehints;
    }

    ret = fi_fabric(rd_info->fabric_attr, &mxr_fabric->rd_fabric, context);
    if (ret) {
        goto freeinfo;
    }

    mxr_fabric->rd_info = rd_info;

    *fabric = &mxr_fabric->util_fabric.fabric_fid;
    (*fabric)->fid.ops = &mxr_fabric_fi_ops;
    (*fabric)->ops = &mxr_fabric_ops;

    free(hints.fabric_attr);
    return 0;
freeinfo:
    fi_freeinfo(rd_info);
freehints:
    free(hints.fabric_attr);
closefabric:
    ofi_fabric_close(&mxr_fabric->util_fabric);
freefabric:
    free(mxr_fabric);
    return ret;
}
