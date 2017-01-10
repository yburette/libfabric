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

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <rdma/fabric.h>
#include <rdma/fi_atomic.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_eq.h>
#include <rdma/fi_errno.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_tagged.h>
#include <rdma/fi_trigger.h>
#include <rdma/providers/fi_prov.h>
#include <rdma/providers/fi_log.h>

#include <fi.h>
#include <fi_proto.h>
#include <fi_enosys.h>
#include <fi_indexer.h>
#include <fi_rbuf.h>
#include <fi_list.h>
#include <fi_signal.h>
#include <fi_util.h>

#include <pthread.h>

#ifndef _MXR_H_
#define _MXR_H_

#define MXR_MAJOR_VERSION 1
#define MXR_MINOR_VERSION 0

#define MXR_CONN_REQ  0x1
#define MXR_CONN_REJ  0x2
#define MXR_CONN_RESP 0x4
#define MXR_CONN_ACK  0x8

#define MXR_MAX_CM_SIZE 1024

extern struct fi_provider mxr_prov;
extern struct util_prov mxr_util_prov;
extern struct fi_info mxr_info;
extern struct fi_info rd_hints;
extern struct fi_fabric_attr mxr_fabric_attr;

struct mxr_fid_domain {
    struct util_domain util_domain;
    struct fid_domain *rd_domain;
    struct mxr_fid_fabric *mxr_fabric;
    struct fid_av *rd_av;
    int refcnt;
};

struct mxr_fid_fabric {
    struct util_fabric util_fabric;
    struct fid_fabric *rd_fabric;
    struct mxr_fid_domain *mxr_domain;
    struct fi_info *rd_info;
    int refcnt;
};

struct mxr_fid_eq {
    struct fid_eq eq;
    struct fid_domain *rd_domain;
    struct fid_cq *rd_cq;
    struct fi_cq_attr cq_attr;
    struct mxr_fid_pep *mxr_pep;
    struct mxr_fid_ep *mxr_ep;
    struct fi_eq_err_entry error;
    struct mxr_conn_buf *error_conn_buf;
    struct fi_eq_cm_entry *shutdown_entry;
    /* TODO: Add connreqs + fi_cancel + free */
    struct slist connreqs;
};

struct mxr_thread_data;

struct mxr_fid_pep {
    struct fid_pep pep;
    struct fid_ep *ctrl_ep;
    struct fi_info *info;
    size_t epnamelen;
    struct mxr_fid_fabric *mxr_fabric;
    struct mxr_fid_domain *mxr_domain;
    struct mxr_fid_eq *mxr_eq;
    struct mxr_thread_data *tdata;
    pthread_t nameserver_thread;
    struct sockaddr bound_addr;
    size_t bound_addrlen;
};

struct mxr_fid_ep {
    struct fid_ep ep;
    struct fid_ep *ctrl_ep;
    struct fid_ep *data_ep;
    struct mxr_fid_eq *mxr_eq;
    struct mxr_fid_domain *mxr_domain;
    struct mxr_fid_pep *pep;
    void *peer_ctrl_epname;
    void *peer_data_epname;
    fi_addr_t peer_ctrl_addr;
    fi_addr_t peer_data_addr;
    int connected;
    struct sockaddr bound_addr;
    size_t bound_addrlen;
    struct dlist_entry reqs;
};

struct mxr_conn_hdr {
    int type;
    size_t cm_datalen;
    char cm_data[MXR_MAX_CM_SIZE];
};

struct mxr_conn_pkt {
    struct mxr_conn_hdr hdr;
    char epnames[FI_NAME_MAX*2];
};

struct mxr_conn_buf {
    struct fi_context ctx;
    struct slist_entry list_entry;
    struct mxr_fid_ep *mxr_ep;
    struct mxr_conn_pkt data;
};

#define TO_MXR_CONN_BUF(_ctx_ptr) \
    container_of(_ctx_ptr, struct mxr_conn_buf, ctx);

struct mxr_request {
    struct fi_context ctx;
    struct dlist_entry list_entry;
    void *user_ptr;
};

#define TO_MXR_REQ(_ctx_ptr) \
    container_of(_ctx_ptr, struct mxr_request, ctx);

int mxr_fabric(struct fi_fabric_attr *attr, struct fid_fabric **fabric,
        void *context);

int mxr_passive_ep(struct fid_fabric *fabric, struct fi_info *info,
        struct fid_pep **pep, void *context);

int mxr_eq_open(struct fid_fabric *fabric, struct fi_eq_attr *attr,
        struct fid_eq **eq, void *context);

int mxr_domain_open(struct fid_fabric *fabric, struct fi_info *info,
        struct fid_domain **domain, void *context);

int mxr_ep_open(struct fid_domain *domain, struct fi_info *info,
        struct fid_ep **ep, void *context);

int mxr_alter_base_info(struct fi_info *base_info, struct fi_info *layer_info);

int mxr_alter_layer_info(struct fi_info *layer_info, struct fi_info *base_info);

int	mxr_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr,
        struct fid_cq **cq, void *context);

int prepare_cm_req(struct mxr_conn_buf *req, int type,
        struct mxr_fid_ep *mxr_ep, const void *param, size_t paramlen,
        size_t *len);

int mxr_start_nameserver(struct mxr_fid_pep *mxr_pep);

int mxr_stop_nameserver(struct mxr_fid_pep *mxr_pep);

void print_address(const char *what, void *data);

#endif /* _MXR_H_ */
