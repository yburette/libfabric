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

static ssize_t mrail_ep_read(struct fid_ep *ep_fid, void *buf, size_t len,
		void *desc, fi_addr_t src_addr, uint64_t addr,
		uint64_t key, void *context)
{
	struct mrail_ep *mrail_ep;
	struct mrail_mr_map_raw *mr_map;
	fi_addr_t *rail_fi_addr;
	uint32_t rail;
	void *rail_desc;
	ssize_t ret;

	mrail_ep = container_of(ep_fid, struct mrail_ep, util_ep.ep_fid.fid);
	mr_map = (struct mrail_mr_map_raw*)key;
	rail_fi_addr = ofi_av_get_addr(mrail_ep->util_ep.av, (int)src_addr);
	rail = mrail_get_rma_rail(mrail_ep);
	rail_desc = NULL;

	assert(rail_fi_addr);

	if (desc) {
		struct mrail_mr *mrail_mr = desc;
		rail_desc = fi_mr_desc(mrail_mr->mrs[rail]);
	}

	ret = fi_read(mrail_ep->eps[rail], buf, len, rail_desc,
			rail_fi_addr[rail], addr, mr_map->rkeys[rail],
			context);
	if (ret) {
		FI_WARN(&mrail_prov, FI_LOG_EP_DATA,
			"Unable to post read on rail: %" PRIu32 "\n", rail);
		return ret;
	}

	return 0;
}

static ssize_t mrail_ep_write(struct fid_ep *ep_fid, const void *buf,
		size_t len, void *desc, fi_addr_t dest_addr, uint64_t addr,
		uint64_t key, void *context)
{
	struct mrail_ep *mrail_ep;
	struct mrail_mr_map_raw *mr_map;
	fi_addr_t *rail_fi_addr;
	uint32_t rail;
	void *rail_desc;
	ssize_t ret;

	mrail_ep = container_of(ep_fid, struct mrail_ep, util_ep.ep_fid.fid);
	mr_map = (struct mrail_mr_map_raw*)key;
	rail_fi_addr = ofi_av_get_addr(mrail_ep->util_ep.av, (int)dest_addr);
	rail = mrail_get_rma_rail(mrail_ep);
	rail_desc = NULL;

	assert(rail_fi_addr);

	if (desc) {
		struct mrail_mr *mrail_mr = desc;
		rail_desc = fi_mr_desc(mrail_mr->mrs[rail]);
	}

	ret = fi_write(mrail_ep->eps[rail], buf, len, rail_desc,
			rail_fi_addr[rail], addr, mr_map->rkeys[rail],
			context);
	if (ret) {
		FI_WARN(&mrail_prov, FI_LOG_EP_DATA,
			"Unable to post write on rail: %" PRIu32 " code=%ld\n",
			rail, ret);
		return ret;
	}

	return 0;
}

static ssize_t mrail_ep_inject_write(struct fid_ep *ep_fid, const void *buf,
		size_t len, fi_addr_t dest_addr, uint64_t addr, uint64_t key)
{
	struct mrail_ep *mrail_ep;
	struct mrail_mr_map_raw *mr_map;
	fi_addr_t *rail_fi_addr;
	uint32_t rail;
	ssize_t ret;

	mrail_ep = container_of(ep_fid, struct mrail_ep, util_ep.ep_fid.fid);
	mr_map = (struct mrail_mr_map_raw*)key;
	rail_fi_addr = ofi_av_get_addr(mrail_ep->util_ep.av, (int)dest_addr);
	rail = mrail_get_rma_rail(mrail_ep);

	assert(rail_fi_addr);

	ret = fi_inject_write(mrail_ep->eps[rail], buf, len, rail_fi_addr[rail],
			addr, mr_map->rkeys[rail]);
	if (ret) {
		FI_WARN(&mrail_prov, FI_LOG_EP_DATA,
			"Unable to post inject write on rail: %" PRIu32 "\n",
			rail);
		return ret;
	}

	return 0;
}

static ssize_t mrail_ep_writedata(struct fid_ep *ep_fid, const void *buf,
		size_t len, void *desc, uint64_t data, fi_addr_t dest_addr,
		uint64_t addr, uint64_t key, void *context)
{
	struct mrail_ep *mrail_ep;
	struct mrail_mr_map_raw *mr_map;
	fi_addr_t *rail_fi_addr;
	uint32_t rail;
	void *rail_desc;
	ssize_t ret;

	mrail_ep = container_of(ep_fid, struct mrail_ep, util_ep.ep_fid.fid);
	mr_map = (struct mrail_mr_map_raw*)key;
	rail_fi_addr = ofi_av_get_addr(mrail_ep->util_ep.av, (int)dest_addr);
	rail = mrail_get_rma_rail(mrail_ep);
	rail_desc = NULL;

	assert(rail_fi_addr);

	if (desc) {
		struct mrail_mr *mrail_mr = desc;
		rail_desc = fi_mr_desc(mrail_mr->mrs[rail]);
	}

	ret = fi_writedata(mrail_ep->eps[rail], buf, len, rail_desc, data,
			rail_fi_addr[rail], addr, mr_map->rkeys[rail],
			context);
	if (ret) {
		FI_WARN(&mrail_prov, FI_LOG_EP_DATA,
			"Unable to post writedata, rail: %" PRIu32 " code=%ld\n",
			rail, ret);
		return ret;
	}

	return 0;
}

static ssize_t mrail_ep_injectdata(struct fid_ep *ep_fid, const void *buf,
		size_t len, uint64_t data, fi_addr_t dest_addr, uint64_t addr,
		uint64_t key)
{
	struct mrail_ep *mrail_ep;
	struct mrail_mr_map_raw *mr_map;
	fi_addr_t *rail_fi_addr;
	uint32_t rail;
	ssize_t ret;

	mrail_ep = container_of(ep_fid, struct mrail_ep, util_ep.ep_fid.fid);
	mr_map = (struct mrail_mr_map_raw*)key;
	rail_fi_addr = ofi_av_get_addr(mrail_ep->util_ep.av, (int)dest_addr);
	rail = mrail_get_rma_rail(mrail_ep);

	assert(rail_fi_addr);

	ret = fi_inject_writedata(mrail_ep->eps[rail], buf, len, data,
			rail_fi_addr[rail], addr, mr_map->rkeys[rail]);
	if (ret) {
		FI_WARN(&mrail_prov, FI_LOG_EP_DATA,
			"Unable to post inject writedata, rail: %" PRIu32 "\n",
			rail);
		return ret;
	}

	return 0;
}

struct fi_ops_rma mrail_ops_rma = {
	.size = sizeof (struct fi_ops_rma),
	.read = mrail_ep_read,
	.readv = fi_no_rma_readv,
	.readmsg = fi_no_rma_readmsg,
	.write = mrail_ep_write,
	.writev = fi_no_rma_writev,
	.writemsg = fi_no_rma_writemsg,
	.inject = mrail_ep_inject_write,
	.writedata = mrail_ep_writedata,
	.injectdata = mrail_ep_injectdata,
};

