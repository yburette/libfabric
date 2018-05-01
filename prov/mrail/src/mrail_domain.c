/*
 * Copyright (c) 2018 Intel Corporation, Inc.  All rights reserved.
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

#include "mrail.h"

static int mrail_domain_close(fid_t fid)
{
	struct mrail_domain *mrail_domain =
		container_of(fid, struct mrail_domain, util_domain.domain_fid.fid);
	int ret, retv = 0;

	ret = mrail_close_fids((struct fid **)mrail_domain->domains,
			       mrail_domain->num_domains);
	if (ret)
		retv = ret;
	free(mrail_domain->domains);

	ret = ofi_domain_close(&mrail_domain->util_domain);
	if (ret)
		retv = ret;

	free(mrail_domain);
	return retv;
}

static int mrail_domain_map_raw(struct mrail_domain *mrail_domain,
                                struct fi_mr_map_raw *map)
{
	struct mrail_mr_map_raw *mr_map;

	mr_map = calloc(1, sizeof(*mr_map));
	if (!mr_map) {
		return -FI_ENOMEM;
	}

	mr_map->rkeys = calloc(1, map->key_size);
	if (!mr_map->rkeys) {
		free(mr_map);
		return -FI_ENOMEM;
	}

	memcpy(mr_map->rkeys, map->raw_key, map->key_size);

	*(map->key) = (uint64_t)mr_map;

	return 0;
}

static int mrail_domain_unmap_key(struct mrail_mr_map_raw **mr_map)
{
	assert(mr_map);
	assert((*mr_map)->rkeys);
	free((*mr_map)->rkeys);
	free(*mr_map);
	return 0;
}

static int mrail_domain_control(struct fid *fid, int command, void *arg)
{
	struct mrail_domain *mrail_domain = container_of(fid,
			struct mrail_domain, util_domain.domain_fid.fid);

	switch(command) {
		case FI_MAP_RAW_MR:
			return mrail_domain_map_raw(mrail_domain, arg);
		case FI_UNMAP_KEY:
			return mrail_domain_unmap_key(arg);
	}
	return -FI_EINVAL;
}

static int mrail_mr_close(fid_t fid)
{
	uint32_t rail;
	struct mrail_mr *mrail_mr = container_of(fid, struct mrail_mr,
			mr_fid.fid);

	for (rail=0; rail<mrail_mr->num_mrs; ++rail) {
		fi_close(&mrail_mr->mrs[rail]->fid);
	}
	return 0;
}

static int mrail_mr_raw_attr(struct mrail_mr *mrail_mr,
                             struct fi_mr_raw_attr *attr)
{
	size_t i;
	uint64_t *key;
	size_t required_key_size = mrail_mr->num_mrs * sizeof(uint64_t);

	if (*(attr->key_size) < required_key_size) {
		*(attr->key_size) = required_key_size;
		return -FI_ETOOSMALL;
	}

	for (i=0, key=(uint64_t*)attr->raw_key; i < mrail_mr->num_mrs;
			++i, ++key) {
		*key = fi_mr_key(mrail_mr->mrs[i]);
	}

	*(attr->key_size) = required_key_size;
	*(attr->base_addr) = mrail_mr->base_addr;

	return 0;
}

static int mrail_mr_control(struct fid *fid, int command, void *arg)
{
	struct mrail_mr *mrail_mr = container_of(fid, struct mrail_mr,
			mr_fid.fid);

	switch(command) {
		case FI_GET_RAW_MR:
			return mrail_mr_raw_attr(mrail_mr, arg);
	}
	return -FI_EINVAL;
}

static struct fi_ops mrail_mr_ops = {
	.size = sizeof(struct fi_ops),
	.close = mrail_mr_close,
	.bind = fi_no_bind,
	.control = mrail_mr_control,
	.ops_open = fi_no_ops_open,
};

static int mrail_mr_reg(struct fid *domain_fid, const void *buf, size_t len,
			 uint64_t access, uint64_t offset, uint64_t requested_key,
			 uint64_t flags, struct fid_mr **mr, void *context)
{
	uint32_t rail;
	struct mrail_mr *mrail_mr;
	struct mrail_domain *mrail_domain = container_of(domain_fid,
			struct mrail_domain, util_domain.domain_fid.fid);
	int ret = 0;

	mrail_mr = calloc(1, sizeof(*mrail_mr));
	if (!mrail_mr) {
		return -FI_ENOMEM;
	}

	mrail_mr->mrs = calloc(mrail_domain->num_domains,
			sizeof(*mrail_mr->mrs));
	if (!mrail_mr->mrs) {
		ret = -FI_ENOMEM;
		goto err1;
	}

	for (rail=0; rail<mrail_domain->num_domains; ++rail) {
		ret = fi_mr_reg(mrail_domain->domains[rail], buf, len, access,
				offset, requested_key, flags,
				&mrail_mr->mrs[rail], context);
		if (ret) {
			FI_WARN(&mrail_prov, FI_LOG_DOMAIN,
				"Unable to register memory, rail %" PRIu32 "\n",
			       	rail);
			goto err2;
		}
	}

	mrail_mr->mr_fid.fid.fclass = FI_CLASS_MR;
	mrail_mr->mr_fid.fid.context = context;
	mrail_mr->mr_fid.fid.ops = &mrail_mr_ops;
	mrail_mr->mr_fid.mem_desc = mrail_mr;
	mrail_mr->mr_fid.key = fi_mr_key(mrail_mr->mrs[0]);
	mrail_mr->num_mrs = mrail_domain->num_domains;
	*mr = &mrail_mr->mr_fid;

	return 0;
err2:
	for (; rail>=0; --rail) {
		fi_close(&mrail_mr->mrs[rail]->fid);
	}
	free(mrail_mr->mrs);
err1:
	free(mrail_mr);
	return ret;
}

static struct fi_ops_mr mrail_domain_mr_ops = {
	.size = sizeof(struct fi_ops_mr),
	.reg = mrail_mr_reg,
	.regv = fi_no_mr_regv,
	.regattr = fi_no_mr_regattr,
};

static struct fi_ops mrail_domain_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = mrail_domain_close,
	.bind = fi_no_bind,
	.control = mrail_domain_control,
	.ops_open = fi_no_ops_open,
};

static struct fi_ops_domain mrail_domain_ops = {
	.size = sizeof(struct fi_ops_domain),
	.av_open = mrail_av_open,
	.cq_open = mrail_cq_open,
	.endpoint = mrail_ep_open,
	.scalable_ep = fi_no_scalable_ep,
	.cntr_open = fi_no_cntr_open,
	.poll_open = fi_no_poll_open,
	.stx_ctx = fi_no_stx_context,
	.srx_ctx = fi_no_srx_context,
	.query_atomic = fi_no_query_atomic,
};

int mrail_domain_open(struct fid_fabric *fabric, struct fi_info *info,
		      struct fid_domain **domain, void *context)
{
	struct mrail_fabric *mrail_fabric =
		container_of(fabric, struct mrail_fabric, util_fabric.fabric_fid);
	struct mrail_domain *mrail_domain;
	struct fi_info *fi;
	size_t i;
	int ret;

	assert(!strcmp(mrail_fabric->info->fabric_attr->name, info->fabric_attr->name));

	mrail_domain = calloc(1, sizeof(*mrail_domain));
	if (!mrail_domain)
		return -FI_ENOMEM;

	ret = ofi_domain_init(fabric, info, &mrail_domain->util_domain, context);
	if (ret) {
		free(mrail_domain);
		return ret;
	}

	mrail_domain->info = mrail_fabric->info;
	mrail_domain->num_domains = mrail_fabric->num_fabrics;

	mrail_domain->domains = calloc(mrail_domain->num_domains,
			sizeof(*mrail_domain->domains));
	if (!mrail_domain->domains) {
		ret = -FI_ENOMEM;
		goto err;
	}

	for (i = 0, fi = mrail_domain->info->next; fi; fi = fi->next, i++) {
		ret = fi_domain(mrail_fabric->fabrics[i], fi,
				&mrail_domain->domains[i], context);
		if (ret)
			goto err;

		mrail_domain->addrlen += fi->src_addrlen;
	}

	*domain = &mrail_domain->util_domain.domain_fid;
	(*domain)->fid.ops = &mrail_domain_fi_ops;
	(*domain)->mr = &mrail_domain_mr_ops;
	(*domain)->ops = &mrail_domain_ops;

	return 0;
err:
	mrail_domain_close(&mrail_domain->util_domain.domain_fid.fid);
	return ret;
}
