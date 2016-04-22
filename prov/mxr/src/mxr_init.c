/*
 * Copyright (c) 2016 Intel Corporation. All rights reserved.
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

#include <rdma/fi_errno.h>

#include <prov.h>
#include "mxr.h"

static int already_in_mxr_getinfo = 0;

int mxr_alter_layer_info(struct fi_info *layer_info, struct fi_info *base_info)
{
    /* 
     * layer_info: hints from the user.
     * base_info : empty info which will be used to
     *             retrieve underlying provider.
     * Note: addresses will be duplicated as part of ofix_alter_layer_info().
     */

    /* Underlying provider needs to be FI_EP_RDM */
    base_info->ep_attr->type = FI_EP_RDM;

    if (NULL == layer_info) {
        return 0;
    }

    base_info->caps = layer_info->caps & ~(mxr_info.caps);
    base_info->mode = 0;
    base_info->domain_attr->cq_data_size =
        layer_info->domain_attr->cq_data_size;
    base_info->domain_attr->resource_mgmt =
        layer_info->domain_attr->resource_mgmt;

    return 0;
}

int mxr_alter_base_info(struct fi_info *base_info, struct fi_info *layer_info)
{
    /* 
     * base_info : info from the underlying provider.
     * layer_info: empty info which will be returned to user. 
     * Note: addresses will be duplicated as part of ofix_alter_base_info().
     */

    /* Add our capabilities */
    layer_info->caps = base_info->caps | mxr_info.caps;
    layer_info->mode = base_info->mode;

    *layer_info->tx_attr = *base_info->tx_attr;
    *layer_info->rx_attr = *base_info->rx_attr;
    /* Replace EP attributes with ours */
    *layer_info->ep_attr = *base_info->ep_attr;
    layer_info->ep_attr->type = mxr_info.ep_attr->type;
    layer_info->ep_attr->protocol = mxr_info.ep_attr->protocol;
    layer_info->ep_attr->protocol_version = mxr_info.ep_attr->protocol_version;
    *layer_info->domain_attr = *base_info->domain_attr;
    /* Use our domain name */
    layer_info->domain_attr->name = strdup(mxr_info.domain_attr->name);
    *layer_info->fabric_attr = *base_info->fabric_attr;
    /* Return our provider name */
    layer_info->fabric_attr->prov_name = mxr_info.fabric_attr->prov_name;

    return 0;
}

static int mxr_getinfo(uint32_t version, const char *node, const char *service,
        uint64_t flags, struct fi_info *hints, struct fi_info **info)
{
    int ret;
    if (already_in_mxr_getinfo) {
        return -FI_ENODATA;
    }
    already_in_mxr_getinfo = 1;
    ret = ofix_getinfo(version, node, service, flags, &mxr_util_prov,
            hints, mxr_alter_layer_info, mxr_alter_base_info, 0, info);
    already_in_mxr_getinfo = 0;
    return ret;
}

static void mxr_fini(void)
{
	/* yawn */
}

struct fi_provider mxr_prov = {
	.name = "mxr",
	.version = FI_VERSION(MXR_MAJOR_VERSION, MXR_MINOR_VERSION),
	.fi_version = FI_VERSION(1, 3),
	.getinfo = mxr_getinfo,
	.fabric = mxr_fabric,
	.cleanup = mxr_fini
};

MXR_INI
{
	return &mxr_prov;
}
