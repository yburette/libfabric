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

struct fi_tx_attr rd_tx_attr = {
    .caps = FI_MSG | FI_SEND,
    .op_flags = FI_INJECT_COMPLETE, /* TODO: Is this needed? */
    .comp_order = FI_ORDER_NONE /* TODO: is this an issue? */
};

struct fi_rx_attr rd_rx_attr = {
    .caps = FI_MSG | FI_RECV | FI_SOURCE,
    .comp_order = FI_ORDER_NONE /* TODO: is this an issue? */
};

struct fi_ep_attr rd_ep_attr = {
    .type = FI_EP_RDM,
    .tx_ctx_cnt = 1, /* TODO: why? */
    .rx_ctx_cnt = 1  /* TODO: why? */
};

struct fi_domain_attr rd_domain_attr = {
    .threading = FI_THREAD_ENDPOINT, /* TODO: review */
    .control_progress = FI_PROGRESS_MANUAL,
    .data_progress = FI_PROGRESS_MANUAL,
    .resource_mgmt = FI_RM_ENABLED,
    .av_type = FI_AV_TABLE,
    .mr_mode = FI_MR_SCALABLE,
    .tx_ctx_cnt = 1, /* TODO: why? */
    .rx_ctx_cnt = 1, /* TODO: why? */
    .max_ep_tx_ctx = 1, /* TODO: why? */
    .max_ep_rx_ctx = 1  /* TODO: why? */
};

struct fi_info rd_hints = {
    .caps = FI_MSG | FI_SEND | FI_RECV | FI_RMA,
    .mode = FI_CONTEXT,
    .addr_format = FI_FORMAT_UNSPEC,
    .tx_attr = &rd_tx_attr,
    .rx_attr = &rd_rx_attr,
    .ep_attr = &rd_ep_attr,
    .domain_attr = &rd_domain_attr
};

struct fi_tx_attr mxr_tx_attr = {
    .caps = FI_MSG | FI_SEND,
    .comp_order = FI_ORDER_STRICT
};

struct fi_rx_attr mxr_rx_attr = {
    .caps = FI_MSG | FI_RECV | FI_SOURCE,
    .comp_order = FI_ORDER_STRICT
};

struct fi_ep_attr mxr_ep_attr = {
    .type = FI_EP_MSG,
    .protocol = FI_PROTO_MXR,
    .protocol_version = 1,
};

struct fi_domain_attr mxr_domain_attr = {
    .name = "mxr",
    .cq_data_size = 4,
    .resource_mgmt = FI_RM_ENABLED,
#if 0
    .threading = FI_THREAD_SAFE,
    .control_progress = FI_PROGRESS_AUTO,
    .data_progress = FI_PROGRESS_AUTO,
    .av_type = FI_AV_UNSPEC,
    .mr_mode = FI_MR_SCALABLE,
    .cq_cnt = 1, /* TODO: why? */
    .ep_cnt = 1, /* TODO: why? */
    .tx_ctx_cnt = 1, /* TODO: why? */
    .rx_ctx_cnt = 1, /* TODO: why? */
    .max_ep_tx_ctx = 1, /* TODO: why? */
    .max_ep_rx_ctx = 1  /* TODO: why? */
#endif
};

struct fi_fabric_attr mxr_fabric_attr = {
    .name = "",
    .prov_version = FI_VERSION(MXR_MAJOR_VERSION, MXR_MINOR_VERSION),
    .prov_name = "mxr"
};

struct fi_info mxr_info = {
    .caps = FI_MSG | FI_RMA,
    .mode = 0, /* Not requesting any specific mode */
    .addr_format = FI_SOCKADDR,
    .tx_attr = &mxr_tx_attr,
    .rx_attr = &mxr_rx_attr,
    .ep_attr = &mxr_ep_attr,
    .domain_attr = &mxr_domain_attr,
    .fabric_attr = &mxr_fabric_attr
};

struct util_prov mxr_util_prov = {
    .prov = &mxr_prov,
    .info = &mxr_info,
    .flags = 0,
};
