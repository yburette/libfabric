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

int mxr_alter_layer_info(struct fi_info *layer_info, struct fi_info **base_info)
{
    struct fi_info *info;

    info = fi_allocinfo();
    if (!info) {
        return -FI_ENOMEM;
    }

    info->mode = FI_CONTEXT;
    info->ep_attr->type = FI_EP_RDM;

    *base_info = info;

    return 0;
}

int mxr_alter_base_info(struct fi_info *base_info, struct fi_info **layer_info)
{
    struct fi_info *info;
    int err;

    info = fi_allocinfo();
    if (!info) {
        return -FI_ENOMEM;
    }

    if (base_info->dest_addr) {
        info->dest_addr = calloc(info->dest_addrlen, sizeof(char));
        if (!info->dest_addr) {
            err = -FI_ENOMEM;
            goto freeinfo;
        }
        memcpy(info->dest_addr, base_info->dest_addr, base_info->dest_addrlen);
        info->dest_addrlen = base_info->dest_addrlen;
    }

	/* TODO choose caps based on base_info caps */
	info->caps = mxr_info.caps;
	info->mode = mxr_info.mode;

	*info->tx_attr = *mxr_info.tx_attr;
	*info->rx_attr = *mxr_info.rx_attr;
	*info->ep_attr = *mxr_info.ep_attr;
	*info->domain_attr = *mxr_info.domain_attr;

    info->domain_attr->name = ofi_strdup_add_prefix(
                                base_info->domain_attr->name,
                                mxr_info.domain_attr->name);
    if (!info->domain_attr->name) {
		FI_WARN(&mxr_prov, FI_LOG_FABRIC,
				"Unable to alter base provider domain name\n");
        err = -FI_EOTHER;
        goto freedest;
    }

	info->fabric_attr->prov_version = mxr_info.fabric_attr->prov_version;
    info->fabric_attr->name = strdup(base_info->fabric_attr->name);
	if (!info->fabric_attr->name) {
		goto freedest;
    }

    FI_WARN(&mxr_prov, FI_LOG_FABRIC,
            "domain name: %s\n", info->domain_attr->name);
    FI_WARN(&mxr_prov, FI_LOG_FABRIC,
            "base fabric name: %s\n", base_info->fabric_attr->name);
    FI_WARN(&mxr_prov, FI_LOG_FABRIC,
            "base fabric prov_name: %s\n", base_info->fabric_attr->prov_name);

    *layer_info = info;

    return 0;
freedest:
    if (info->dest_addr)
        free(info->dest_addr);
freeinfo:
    fi_freeinfo(info);
    return err;
}

static int mxr_getinfo(uint32_t version, const char *node, const char *service,
        uint64_t flags, struct fi_info *hints, struct fi_info **info)
{
    return ofi_layered_prov_getinfo(version, node, service, flags, &mxr_prov,
                                    &mxr_info, hints, mxr_alter_layer_info,
                                    mxr_alter_base_info, 0, info);
#if 0
	int ret;
	struct fi_info *rd_info;
    struct fi_info *entry;

	if (!hints || !hints->ep_attr || (hints->ep_attr->type != FI_EP_MSG)) {
		return -FI_ENODATA;
    }

    /* TODO: What needs to be done if dst_addr is passed in? */
	ret = fi_getinfo(version, node, service, flags, &rd_hints, &rd_info);
	if (ret) {
		return ret;
    }

    /* TODO: How do we save the original fabric_attr? */

	entry = rd_info;
	while (entry) {
		entry->caps = mxr_info.caps;
		*(entry->tx_attr) = *(mxr_info.tx_attr);
		*(entry->rx_attr) = *(mxr_info.rx_attr);
		*(entry->ep_attr) = *(mxr_info.ep_attr);
		*(entry->fabric_attr) = *(mxr_info.fabric_attr);
		*(entry->domain_attr) = *(mxr_info.domain_attr);
		entry->domain_attr->name = strdup(mxr_info.domain_attr->name);
		entry->fabric_attr->name = strdup(mxr_info.fabric_attr->name);
		entry = entry->next;
	}

	*info = rd_info;
	return 0;
#endif
}

static void mxr_fini(void)
{
	/* yawn */
}

struct fi_provider mxr_prov = {
	.name = "mxr",
	.version = FI_VERSION(MXR_MAJOR_VERSION, MXR_MINOR_VERSION),
	.fi_version = MXR_FI_VERSION,
	.getinfo = mxr_getinfo,
	.fabric = mxr_fabric_open,
	.cleanup = mxr_fini
};

MXR_INI
{
	return &mxr_prov;
}
