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

#include <sys/types.h>
#include <arpa/inet.h>

#include <pthread.h>

#ifndef _MXR_H_
#define _MXR_H_

#define MXR_MAJOR_VERSION 1
#define MXR_MINOR_VERSION 0

#define MXR_CONN_REQ  0x1
#define MXR_CONN_REJ  0x2
#define MXR_CONN_RESP 0x4
#define MXR_CONN_ACK  0x8

#define MXR_MAX_CM_DATA_SIZE 1024
#define MXR_MAX_EQE_SIZE (sizeof(struct fi_eq_cm_entry) + MXR_MAX_CM_DATA_SIZE)

extern struct fi_provider mxr_prov;
extern struct util_prov mxr_util_prov;
extern struct fi_info mxr_info;
extern struct fi_info rd_hints;
extern struct fi_fabric_attr mxr_fabric_attr;

struct mxr_cm_entry;
struct mxr_cm_conn;
struct mxr_cm_listener;

struct mxr_cm_db {
    struct mxr_cm_entry *local_ports;
    struct mxr_cm_entry *remote_ports;
    struct mxr_cm_conn *connections;
    struct mxr_cm_listener *listeners;
};

struct mxr_cm_conn {
    struct sockaddr_in l_sa;
    struct sockaddr_in r_sa;
    struct mxr_fid_ep *ep;
    struct mxr_cm_conn *next;
};

struct mxr_cm_listener {
    struct sockaddr_in l_sa;
    struct mxr_fid_pep *pep;
    struct mxr_cm_listener *next;
};

struct mxr_cm_entry {
    struct sockaddr_in sa;
    char rd_name[FI_NAME_MAX];
    size_t rd_namelen;
    fi_addr_t fi_addr;
    fi_addr_t cm_fi_addr;
    struct mxr_fid_ep *mxr_ep;
    struct mxr_fid_pep *mxr_pep;
    struct mxr_cm_entry *next;
};

struct mxr_fid_domain {
    struct util_domain util_domain;
    struct fid_domain *rd_domain;
    struct mxr_fid_fabric *mxr_fabric;
    struct fid_av *rd_av;
    struct fid_cq *cm_rd_cq;
    struct fid_ep *cm_rd_ep;
    int refcnt;
    struct dlist_entry cm_tx_queue;
    struct dlist_entry cm_rx_queue;
};

struct mxr_fid_fabric {
    struct util_fabric util_fabric;
    struct fid_fabric *rd_fabric;
    struct mxr_fid_domain *domain;
    struct fi_info *rd_info;
    int refcnt;
};

struct mxr_fid_eq {
    struct fid_eq eq_fid;
    struct fid_eq *util_eq;
    struct mxr_fid_domain *domain;
    struct mxr_fid_pep *pep;
    struct mxr_fid_ep *ep;
    struct fi_eq_err_entry error;
    struct mxr_conn_buf *error_conn_buf;
    struct fi_eq_cm_entry *shutdown_entry;
};

struct mxr_fid_cq {
    struct fid_cq cq;
    struct fid_cq *rd_cq;
    enum fi_cq_format format;
};

struct mxr_thread_data;

struct mxr_fid_pep {
    struct fid_pep pep_fid;
    struct sockaddr_in bound_addr;
    struct fi_info *info;
    size_t epnamelen;
    struct mxr_fid_fabric *mxr_fabric;
    struct mxr_fid_domain *mxr_domain;
    struct mxr_fid_eq *eq;
    int registered;
    struct mxr_thread_data *tdata;
    pthread_t nameserver_thread;
};

struct mxr_fid_ep {
    struct fid_ep ep_fid;
    struct mxr_fid_domain *mxr_domain;
    struct fid_ep *rd_ep;
    struct mxr_fid_eq *eq;
    struct mxr_fid_pep *pep;
    struct sockaddr_in bound_addr;
    struct sockaddr_in peer_addr;
    fi_addr_t peer_fi_addr;
    int registered;
    int connected;
    struct dlist_entry reqs;
};

/* mxr_conn_pkt is the data that is sent across the wire for CM operations
 *  - type
 *  - target: address of the message's target (EP or PEP)
 *  - source: address of the message's source (EP or PEP)
 *  - name: EP name (underlying provider)
 *  - cm_name: EP name of the CM
 *  - eqe_buf: contains fi_eq_cm_entry and cm_data
 */
struct mxr_conn_pkt {
    int type;
    struct sockaddr_in target;
    struct sockaddr_in source;
    size_t namelen;
    char name[FI_NAME_MAX];
    size_t cm_namelen;
    char cm_name[FI_NAME_MAX];
    size_t cm_datalen;
    char eqe_buf[MXR_MAX_EQE_SIZE];
};

struct mxr_conn_buf {
    struct fi_context ctx;
    struct dlist_entry list_entry;
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

#define NEW_MXR_REQ(_ep, _req) \
    do { \
        (_req) = calloc(1, sizeof *(_req)); \
        if (!(_req)) { \
            return -FI_ENOMEM; \
        } \
        dlist_insert_head(&(_req)->list_entry, &(_ep)->reqs); \
    } while (0)

struct mxr_fid_fabric *mxr_active_fabric;

/* Global CM database */
struct mxr_cm_db mxr_cm_db;
int mxr_cm_db_init;

int mxr_fabric(struct fi_fabric_attr *attr, struct fid_fabric **fabric,
        void *context);

int mxr_passive_ep(struct fid_fabric *fabric, struct fi_info *info,
        struct fid_pep **pep, void *context);

int	mxr_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr,
        struct fid_cq **cq, void *context);

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
        struct mxr_fid_ep *mxr_ep, const struct sockaddr_in *target,
        struct sockaddr_in *source, const void *param, size_t paramlen);

int mxr_start_nameserver(struct mxr_fid_pep *mxr_pep);

int mxr_stop_nameserver(struct mxr_fid_pep *mxr_pep);

void mxr_cm_init();

void mxr_cm_fini();

ssize_t mxr_cm_register_remote_cm(const struct sockaddr_in *sa, void *name,
        size_t len);

ssize_t mxr_cm_progress(struct mxr_fid_domain *mxr_domain);

void mxr_cm_set_port(struct sockaddr_in *sin, short unsigned int port);

short unsigned int mxr_cm_get_port(const struct sockaddr_in *sin);

int mxr_cm_register_local_port(struct sockaddr_in *sa, struct mxr_fid_pep *pep,
        struct mxr_fid_ep *ep);

int mxr_cm_map_remote_ports(struct mxr_fid_domain *mxr_domain);

#endif /* _MXR_H_ */
