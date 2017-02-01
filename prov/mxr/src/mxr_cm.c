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

int mxr_cm_db_init = 0;

int mxr_cm_reg_conn(struct mxr_fid_ep *ep)
{
    struct mxr_cm_conn *conn;

    conn = calloc(1, sizeof *conn);
    if (!conn) {
        return -FI_ENOMEM;
    }
    memcpy(&conn->l_sa, &ep->bound_addr, sizeof ep->bound_addr);
    memcpy(&conn->r_sa, &ep->peer_addr, sizeof ep->peer_addr);
    conn->ep = ep;
    conn->next = mxr_cm_db.connections;
    mxr_cm_db.connections = conn;

    return 0;
}

struct mxr_fid_ep *mxr_cm_lookup_ep(const struct sockaddr_in *local,
        const struct sockaddr_in *remote)
{
    struct mxr_cm_conn *conn;

    conn = mxr_cm_db.connections;
    while (conn) {
        if ((memcmp(local, &conn->l_sa, sizeof *local) == 0) &&
            (memcmp(remote, &conn->r_sa, sizeof *remote) == 0)) {
            break;
        }
    }
    return (conn ? conn->ep : NULL);
}

int assign_next_available_port(struct sockaddr_in *sa)
{
    struct mxr_cm_listener *l;
    struct mxr_cm_listener *cur;

    l = calloc(1, sizeof *l);
    if (!l) {
        return -FI_ENOMEM;
    }

    cur = mxr_cm_db.listeners;

    if (!cur || (mxr_cm_get_port(&cur->l_sa) > 1)) {
        /* Assign first port */
        mxr_cm_set_port(sa, 1);
        l->next = cur;
        mxr_cm_db.listeners = l;
    } else {
        /* Walk through list until gap is found */
        while (cur->next &&
               (mxr_cm_get_port(&cur->next->l_sa) -
                mxr_cm_get_port(&cur->l_sa)) == 1) {
            cur = cur->next;
        }
        mxr_cm_set_port(sa, mxr_cm_get_port(&cur->l_sa) + 1);
        l->next = cur->next;
        cur->next = l;
    }

    return 0;
}

#if 0
int mxr_cm_reg_listener(struct mxr_fid_pep *pep)
{
    int ret;
    struct mxr_cm_listener *l;
    struct mxr_cm_listener *cur;

    if (!mxr_cm_db.listeners) {
        /* Empty list; insert at the head */
        if (mxr_cm_get_port(&pep->bound_addr) == 0) {
            /* Assign first port */
            mxr_cm_set_port(&pep->bound_addr, 1);
        }
        l->next = NULL;
        mxr_cm_db.listeners = l;
    } else {
        cur = mxr_cm_db.listeners;
    
        if (mxr_cm_get_port(&pep->bound_addr) == 0) {
            /* Find next available port */
            if (mxr_cm_get_port(&cur->l_sa) > 1) {
                /* First port; insert at the head */
                mxr_cm_set_port(&pep->bound_addr, 1);
                l->next = cur;
                mxr_cm_db.listeners = l;
            } else {
                /* Walk through the list to find next available port */
                while (cur->next &&
                        (mxr_cm_get_port(&cur->next->l_sa) -
                         mxr_cm_get_port(&cur->l_sa) == 1)) {
                    cur = cur->next;
                }
                mxr_cm_set_port(&pep->bound_addr,
                                mxr_cm_get_port(&cur->l_sa) + 1);
                l->next = cur->next;
                cur->next = l;
            }
        } else {
            /* A port was specified; insert in ordered list */
            while (mxr_cm_get_port(&cur->l_sa) <
                   mxr_cm_get_port(&pep->bound_addr)) {
                cur = cur->next;
            }
            if (mxr_cm_get_port(&cur->l_sa) ==
                mxr_cm_get_port(&pep->bound_addr)) {
                FI_WARN(&mxr_prov, FI_LOG_FABRIC, "Port already registered\n");
                free(l);
                return -FI_EINVAL;
            }
            l->next = cur->next;
            cur->next = l;
        }
    }

    memcpy(&l->l_sa, &pep->bound_addr, sizeof pep->bound_addr);

    return 0;
}
#endif

struct mxr_fid_pep *mxr_cm_lookup_pep(const struct sockaddr_in *local)
{
    struct mxr_cm_entry *e;

    /* TODO: list is now ordered; this can be optimized */
    e = mxr_cm_db.local_ports;
    while (e) {
        if (memcmp(local, &e->sa, sizeof *local) == 0) {
            break;
        }
        e = e->next;
    }
    return (e ? e->mxr_pep : NULL);
}


inline
short unsigned int mxr_cm_get_port(const struct sockaddr_in *sin)
{
    return ntohs(sin->sin_port);
}

inline
void mxr_cm_set_port(struct sockaddr_in *sin, short unsigned int port)
{
    sin->sin_port = htons(port);
}

#if 1

int mxr_cm_register_local_port(struct sockaddr_in *sa, struct mxr_fid_pep *pep,
        struct mxr_fid_ep *ep)
{
    struct mxr_cm_entry *cur;
    struct mxr_cm_entry *e;

#define MXR_FIRST_PORT 1025

    if ((ep && ep->registered) || (pep && pep->registered)) {
        return -FI_EINVAL;
    }

    e = calloc(1, sizeof *e);
    if (!e) {
        return -FI_ENOMEM;
    }
    memcpy(&e->sa, sa, sizeof *sa); 
    /* TODO: Make sure that only one of them is != NULL */
    e->mxr_pep = pep;
    e->mxr_ep = ep;

    if (!mxr_cm_db.local_ports) {
        /* Insert at the head */
        if (mxr_cm_get_port(&e->sa) == 0) {
            mxr_cm_set_port(&e->sa, MXR_FIRST_PORT);
            mxr_cm_set_port(sa, MXR_FIRST_PORT);
        }
        e->next = NULL;
        mxr_cm_db.local_ports = e;
        return 0;
    }

    cur = mxr_cm_db.local_ports;

    if (mxr_cm_get_port(&e->sa) == 0) {
        /* Insert at the head */
        if (mxr_cm_get_port(&cur->sa) > MXR_FIRST_PORT) {
            mxr_cm_set_port(&e->sa, MXR_FIRST_PORT);
            mxr_cm_set_port(sa, MXR_FIRST_PORT);
            e->next = mxr_cm_db.local_ports;
            mxr_cm_db.local_ports = e;
            return 0;
        }
        while (cur->next &&
               (mxr_cm_get_port(&cur->next->sa) -
                mxr_cm_get_port(&cur->sa) == 1)) {
            cur = cur->next;
        }
        mxr_cm_set_port(&e->sa, mxr_cm_get_port(&cur->sa) + 1);
        mxr_cm_set_port(sa, mxr_cm_get_port(&cur->sa) + 1);
    } else {
        while (mxr_cm_get_port(&cur->sa) < mxr_cm_get_port(&e->sa)) {
            cur = cur->next;
        }
        if (mxr_cm_get_port(&cur->sa) == mxr_cm_get_port(&e->sa)) {
            FI_WARN(&mxr_prov, FI_LOG_FABRIC, "Error: Already registered\n");
            free(e);
            return -FI_EINVAL;
        }
    }

    e->next = cur->next;
    cur->next = e;

    if (ep) {
        ep->registered = 1;
    } else if (pep) {
        pep->registered = 1;
    }

    return 0;
}
#endif

struct mxr_cm_entry *lookup_cm_entry(const struct sockaddr_in *sa, int is_local)
{
    struct mxr_cm_entry *cur;

    cur = (is_local ? mxr_cm_db.local_ports : mxr_cm_db.remote_ports);

    while (cur) {
        if (memcmp(sa, &cur->sa, sizeof *sa) == 0) {
            break;
        }
        cur = cur->next;
    }

    if (!cur) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "Cannot find CM entry\n");
        return NULL;
    }
    return cur;
}

struct mxr_fid_eq *lookup_local_eq(const struct sockaddr_in *sa)
{
    struct mxr_cm_entry *entry = NULL;

    entry = lookup_cm_entry(sa, 1);
    if (!entry) {
        return NULL;
    }

    if (entry->mxr_ep) {
        return entry->mxr_ep->eq;
    } else if (entry->mxr_pep) {
        return entry->mxr_pep->eq;
    } else {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "Error: No bound EQ");
        return NULL;
    }
}

struct mxr_fid_ep *lookup_local_ep(const struct sockaddr_in *sa)
{
    struct mxr_cm_entry *entry = NULL;

    entry = lookup_cm_entry(sa, 1);
    if (!entry) {
        return NULL;
    }

    return entry->mxr_ep;
}

ssize_t mxr_cm_register_remote_cm(const struct sockaddr_in *sa, void *name,
        size_t len)
{
    struct mxr_cm_entry *entry = NULL;

    entry = lookup_cm_entry(sa, 0);
    if (entry) {
        if (memcmp(name, &entry->rd_name, len) != 0) {
            FI_WARN(&mxr_prov, FI_LOG_FABRIC,
                    "Error: Address already registered with different cm\n");
            return -FI_EINVAL;
        }
    } else {
        entry = calloc(1, sizeof *entry);
        if (!entry) {
            return -FI_ENOMEM;
        }
        entry->fi_addr = FI_ADDR_UNSPEC;
        entry->cm_fi_addr = FI_ADDR_UNSPEC;
        memcpy(&entry->sa, sa, sizeof *sa);
        memcpy(&entry->rd_name, name, len);
        entry->rd_namelen = len;
        
        /* Insert at the head */
        entry->next = mxr_cm_db.remote_ports;
        mxr_cm_db.remote_ports = entry;
    }

    return 0;
}

ssize_t get_remote_cm_fi_addr(struct mxr_fid_domain *mxr_domain,
        const struct sockaddr_in *sa, fi_addr_t *fi_addr)
{
    ssize_t ret;
    struct mxr_cm_entry *entry = NULL;

    entry = lookup_cm_entry(sa, 0);
    if (!entry) {
        return -FI_EINVAL;
    }

    if (entry->cm_fi_addr == FI_ADDR_UNSPEC) {
        ret = fi_av_insert(mxr_domain->rd_av, entry->rd_name, 1,
                           &entry->cm_fi_addr, 0, NULL);
        if (ret != 1) {
            return ret;
        }
    }

    *fi_addr = entry->cm_fi_addr;

    return 0;
}

void mxr_cm_fini()
{
    struct mxr_cm_entry *e;
    struct mxr_cm_conn *c;
    struct mxr_cm_listener *l;
    void *tmp;

    if (mxr_cm_db_init == 0) {
        return;
    }

    e = mxr_cm_db.local_ports;
    while (e) {
        tmp = e->next;
        free(e);
        e = tmp;
    }
    mxr_cm_db.local_ports = NULL;

    e = mxr_cm_db.remote_ports;
    while (e) {
        tmp = e->next;
        free(e);
        e = tmp;
    }
    mxr_cm_db.remote_ports = NULL;

    c = mxr_cm_db.connections;
    while (c) {
        tmp = c->next;
        free(c);
        c = tmp;
    }
    mxr_cm_db.connections = NULL;

    l = mxr_cm_db.listeners;
    while (l) {
        tmp = l->next;
        free(l);
        l = tmp;
    }
    mxr_cm_db.listeners = NULL;

    mxr_cm_db_init = 0;
}

void mxr_cm_init()
{
    if (mxr_cm_db_init == 0) {
        mxr_cm_db.local_ports = NULL;
        mxr_cm_db.remote_ports = NULL;
        mxr_cm_db.connections = NULL;
        mxr_cm_db.listeners = NULL;
        mxr_cm_db_init = 1;
    }
}

#if 0

inline
size_t extract_cm_data(struct fi_eq_cm_entry *entry, struct mxr_conn_buf *buf)
{
    size_t datalen = buf->data.cm_datalen;
    if (datalen) {
        memcpy(&entry->data, buf->data.cm_data, datalen);
    }
    return datalen;
}
#endif

#if 0

int mxr_cm_map_remote_ports(struct mxr_fid_domain *mxr_domain)
{
    int ret;
    char ip4[INET_ADDRSTRLEN];
    struct mxr_cm_entry *cur = mxr_cm_db.remote_ports;

    FI_INFO(&mxr_prov, FI_LOG_INFO, "Mapping remote ports...\n");
    while(cur) {
        inet_ntop(AF_INET, &cur->sa.sin_addr, ip4, INET_ADDRSTRLEN);
        FI_INFO(&mxr_prov, FI_LOG_INFO, " - map %s:%d\n",
                ip4, mxr_cm_get_port(&cur->sa));
        /* TODO: set flags to FI_MORE */
        ret = fi_av_insert(mxr_domain->av, cur->rd_name, 1,
                           &cur->fi_addr, 0, NULL);
        if (ret) {
            FI_WARN(&mxr_prov, FI_LOG_FABRIC, "Error AV insert: %d\n", ret);
            return ret;
        }
        cur = cur->next;
    }
    FI_INFO(&mxr_prov, FI_LOG_INFO, "Finished mapping remote ports\n");

    return 0;
}
#endif

ssize_t mxr_cm_send(int type, struct mxr_fid_ep *ep,
        const struct sockaddr_in *target, const void *param, size_t paramlen)
{
    ssize_t ret;
    struct mxr_conn_buf *cm_buf;
    struct fi_eq_cm_entry *eqe;
    fi_addr_t remote_cm;

#if 0
    if (!ep->bound_addr) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "Endpoint bound address not set\n");
        return -FI_EINVAL;
    }

    if (!ep->peer_addr) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "Endpoint peer address not set\n");
        return -FI_EINVAL;
    }
#endif

    if (paramlen > MXR_MAX_CM_DATA_SIZE) {
        return -FI_EINVAL;
    }

    ret = get_remote_cm_fi_addr(ep->mxr_domain, &ep->peer_addr, &remote_cm);
    if (ret) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "Cannot find remote CM fi_addr\n");
        return -FI_EINVAL;
    }

    cm_buf = calloc(1, sizeof *cm_buf);
    if (!cm_buf) {
        return -FI_ENOMEM;
    }

    cm_buf->data.type = type;
    memcpy(&cm_buf->data.target, &ep->peer_addr, sizeof ep->peer_addr);
    memcpy(&cm_buf->data.source, &ep->bound_addr, sizeof ep->bound_addr);
    cm_buf->data.cm_datalen = paramlen;
    if (paramlen > 0) {
        eqe = (struct fi_eq_cm_entry *)&cm_buf->data.eqe_buf;
        memcpy(&eqe->data, param, paramlen);
    }

    switch(type) {
    case MXR_CONN_REQ:
        cm_buf->data.namelen = sizeof cm_buf->data.name;
        ret = fi_getname((fid_t)ep->mxr_domain->cm_rd_ep,
                         &cm_buf->data.name, &cm_buf->data.namelen);
        if (ret) {
            goto freebuf;
        }
        break;
    case MXR_CONN_RESP:
#if 0
        cm_buf->data.cm_namelen = sizeof cm_buf->data.cm_name;
        ret = fi_getname((fid_t)ep->mxr_domain->cm_rd_ep, &cm_buf->data.cm_name,
                         &cm_buf->data.cm_namelen);
        if (ret) {
            goto freebuf;
        }
#endif
    case MXR_CONN_ACK:
        cm_buf->data.namelen = sizeof cm_buf->data.name;
        ret = fi_getname((fid_t)ep->rd_ep, &cm_buf->data.name,
                         &cm_buf->data.namelen);
        if (ret) {
            goto freebuf;
        }
        break;
    default:
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "Unknown CM message type\n");
        ret = -FI_EINVAL;
        goto freebuf;
    };

    ret = fi_send(ep->mxr_domain->cm_rd_ep, &cm_buf->data,
                  sizeof(struct mxr_conn_pkt), NULL,
                  remote_cm, (void *)&cm_buf->ctx); 
    if (ret) {
        goto freebuf;
    }

    dlist_insert_head(&cm_buf->list_entry, &ep->mxr_domain->cm_tx_queue);

    return 0;
freebuf:
    free(cm_buf);
    return ret;
}

#if 0

int prepare_cm_req(struct mxr_conn_buf *req, int type,
        struct mxr_fid_ep *mxr_ep, const struct sockaddr_in *target,
        struct sockaddr_in *source, const void *param, size_t paramlen)
{
    int ret;

    req->mxr_ep = mxr_ep;
    req->data.type = type;

    memcpy(&req->data.target, target, sizeof *target);
    memcpy(&req->data.source, source, sizeof *source);

    switch(type) {
    case MXR_CONN_RESP:
    case MXR_CONN_ACK:
        req->data.namelen = sizeof req->data.name;
        ret = fi_getname((fid_t)mxr_ep->rd_ep, &req->data.name,
                         &req->data.namelen);
        if (ret) {
            return ret;
        }
        /* Fall through */
    case MXR_CONN_REJ:
    case MXR_CONN_REQ:
        if (paramlen > 0) {
            if (paramlen > sizeof(req->data.cm_data)) {
                return -FI_EINVAL;
            }
            memcpy((void*)&req->data.cm_data, param, paramlen);
        }
        req->data.cm_datalen = paramlen;
        break;
    default:
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "Unknown cm req type\n");
        return -FI_EINVAL;
    }

    return 0;
}
#endif

int mxr_getname(fid_t fid, void *addr, size_t *addrlen)
{
    struct sockaddr_in *bound_addr;
    struct mxr_fid_pep *pep;
    struct mxr_fid_ep *ep;

    switch (fid->fclass) {
    case FI_CLASS_PEP:
        pep = container_of(fid, struct mxr_fid_pep, pep_fid.fid);
        bound_addr = &pep->bound_addr;
        break;
    case FI_CLASS_EP:
        ep = container_of(fid, struct mxr_fid_ep, ep_fid.fid);
        bound_addr = &ep->bound_addr;
        break;
    default:
        return -FI_EINVAL;
    }

    memcpy(addr, bound_addr, sizeof *bound_addr);
    *addrlen = sizeof *bound_addr;

    return 0;
}

int	mxr_getpeer(struct fid_ep *ep, void *addr, size_t *addrlen)
{
    struct mxr_fid_ep *mxr_ep = (struct mxr_fid_ep *)ep;

#if 0
    if (!mxr_ep->peer_addr) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "EP peer address not set\n");
        return -FI_EINVAL;
    }
#endif

    *addrlen = sizeof mxr_ep->peer_addr;
    memcpy(addr, (void*)&mxr_ep->peer_addr, *addrlen);

    return 0;
}

int mxr_setname(fid_t fid, void *addr, size_t addrlen)
{
    void *bound_addr;
    struct mxr_fid_pep *pep;
    struct mxr_fid_ep *ep;

    /* TODO: Assert that addrlen == sizeof sockaddr_in */

    switch (fid->fclass) {
    case FI_CLASS_PEP:
        pep = container_of(fid, struct mxr_fid_pep, pep_fid.fid);
        bound_addr = &pep->bound_addr;
        break;
    case FI_CLASS_EP:
        ep = container_of(fid, struct mxr_fid_ep, ep_fid.fid);
        bound_addr = &ep->bound_addr;
        break;
    default:
        return -FI_EINVAL;
    }

    /* TODO: Verify that addrlen == sizeof sockaddr_in */
    memcpy(bound_addr, addr, addrlen);

    return 0;
}

int mxr_connect(struct fid_ep *ep, const void *addr, const void *param,
       size_t paramlen)
{
    /* 
     * Send CONNREQ to the passive side's CM.
     * - get remote CM fi_addr associated with addr
     * - prepare CONNREQ with:
     *   - local EP sockaddr_in
     *   - remote PEP sockaddr_in (== addr)
     *   - local CM rd_name, rd_len
     */
    int ret;
    char ip4[INET_ADDRSTRLEN];
    const struct sockaddr_in *sa = addr;
    struct mxr_fid_ep *mxr_ep = (struct mxr_fid_ep*)ep;

    if (!sa) {
        return -FI_EINVAL;
    }

    /* TODO: Assert */
    if (mxr_ep->registered) {
        return -FI_EINVAL;
    }

#if 1
    ret = mxr_cm_register_local_port(&mxr_ep->bound_addr, NULL, mxr_ep);
    if (ret) {
        return ret;
    }
#endif
    memcpy(&mxr_ep->peer_addr, addr, sizeof mxr_ep->peer_addr);

    ret = mxr_cm_reg_conn(mxr_ep);
    if (ret) {
        return ret;
    }

    ret = fi_enable(mxr_ep->rd_ep);
    if (ret) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "Could not enable EP: %d\n", ret);
        return ret;
    }

    inet_ntop(AF_INET, &sa->sin_addr, ip4, INET_ADDRSTRLEN);
    FI_INFO(&mxr_prov, FI_LOG_INFO, "Connecting EP %p to %s:%d...\n",
            mxr_ep, ip4, mxr_cm_get_port(sa));

    return mxr_cm_send(MXR_CONN_REQ, mxr_ep, sa, param, paramlen);
} 

int mxr_listen(struct fid_pep *pep)
{
    int ret;
    char ip4[INET_ADDRSTRLEN];
    struct mxr_fid_pep *mxr_pep;
    
    mxr_pep = container_of(pep, struct mxr_fid_pep, pep_fid.fid);

    inet_ntop(AF_INET, &mxr_pep->bound_addr.sin_addr, ip4, INET_ADDRSTRLEN);
    FI_INFO(&mxr_prov, FI_LOG_INFO, "Registering PEP %p at %s:%d...\n",
            mxr_pep, ip4, ntohs(mxr_pep->bound_addr.sin_port));

#if 0
    ret = mxr_cm_reg_listener(mxr_pep);
#else
    ret = mxr_cm_register_local_port(&mxr_pep->bound_addr, mxr_pep, NULL);
#endif
    if (ret) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "Could not register PEP: %d\n", ret);
        return -FI_EINVAL;
    }

    FI_INFO(&mxr_prov, FI_LOG_INFO, "PEP %p listening on %s:%d...\n",
            mxr_pep, ip4, ntohs(mxr_pep->bound_addr.sin_port));

    return 0;
}

int mxr_accept(struct fid_ep *ep, const void *param, size_t paramlen)
{
    /*
     * Send CONNRESP to remote CM.
     * - get remote CM fi_addr_t associated with peer_addr
     * - prepare CONNRESP with:
     *      - local EP sockaddr
     *      - remote EP sockaddr (peer_addr)
     *      - local EP rd_name, rd_namelen
     */
    int ret;
    char ip4[INET_ADDRSTRLEN];
    struct mxr_fid_ep *mxr_ep = (struct mxr_fid_ep*)ep;

    /* TODO: Assert */
    if (mxr_ep->registered) {
        return -FI_EINVAL;
    }

#if 0
    ret = mxr_cm_register_local_port(&mxr_ep->bound_addr, NULL, mxr_ep);
#endif
    ret = mxr_cm_reg_conn(mxr_ep);
    if (ret) {
        return ret;
    }

    ret = fi_enable(mxr_ep->rd_ep);
    if (ret) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "Could not enable EP: %d\n", ret);
        return ret;
    }

    inet_ntop(AF_INET, &mxr_ep->peer_addr.sin_addr, ip4, INET_ADDRSTRLEN);
    FI_INFO(&mxr_prov, FI_LOG_INFO, "Sending MXR_CONN_RESP from EP %p to %s:%d...\n",
            mxr_ep, ip4, mxr_cm_get_port(&mxr_ep->peer_addr));

    return mxr_cm_send(MXR_CONN_RESP, mxr_ep, &mxr_ep->peer_addr,
                       param, paramlen);
}

int mxr_reject(struct fid_pep *pep, fid_t handle, const void *param,
        size_t paramlen)
{
    /*
     * Send CONNREJ to remote CM.
     * - get remote CM fi_addr_t associated with (handle)->dest_addr 
     * - prepare CONNREJ with:
     *      - local PEP sockaddr
     *      - remote EP sockaddr (handle)->dest_addr
     */

    return -FI_ENOSYS;

#if 0

    

    count = fi_av_insert(mxr_pep->mxr_domain->rd_av,
                         info->dest_addr,
                         1,
                         &remote_fi_addr,
                         0,
                         NULL);
    if (1 != count) {
        return -FI_EOTHER;
    }

    rej = calloc(1, sizeof(struct mxr_conn_buf));
    if (!rej) {
        return -FI_ENOMEM;
    }

    ret = prepare_cm_req(rej, MXR_CONN_REJ, NULL, param, paramlen, &len);
    if (ret) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "prepare_cm_req failed\n");
        goto freerej;
    }

    FI_WARN(&mxr_prov, FI_LOG_FABRIC,
            "Sending a MXR_CONN_REJ (mxr_pep %p)\n", mxr_pep);

    ret = fi_send(mxr_pep->ctrl_ep, &rej->data, len, NULL,
                  remote_fi_addr, (void *) &rej->ctx);
    if(ret) {
        goto freerej;
    }

    return 0;
freerej:
    free(rej);
    return ret;
#endif
}

static int mxr_shutdown(struct fid_ep *ep, uint64_t flags)
{
    int ret;
    struct mxr_fid_ep *mxr_ep = (struct mxr_fid_ep*)ep;
    struct fi_eq_cm_entry *entry;

    if (!mxr_ep->eq) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC,
                "Error: EP %p isn't bound to any EQ\n", mxr_ep);
        return -FI_EINVAL;
    }

    if (mxr_ep->eq->shutdown_entry) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC,
                "Error: shutdown_entry already initialized\n");
        return -FI_EOTHER;
    }

    entry = calloc(1, sizeof(*entry));
    if (!entry) {
        return -FI_ENOMEM;
    }
    entry->fid = &ep->fid;
    mxr_ep->eq->shutdown_entry = entry;

    /* TODO: Notify other side using CM channel */

    ret = fi_shutdown(mxr_ep->rd_ep, flags);
    if (ret) {
        free(entry);
        return ret;
    }

    return 0;
}

ssize_t process_connreq(struct mxr_fid_domain *mxr_domain,
        struct mxr_conn_pkt *pkt)
{
    /*
     * target: local PEP address
     * source: remote EP address
     * name: remote CM name
     */
    ssize_t ret;
    size_t len;
    struct fi_info *info;
    struct fi_eq_cm_entry *eqe;
    struct mxr_fid_pep *pep = NULL;
    struct mxr_fid_eq *eq = NULL;

    /* Lookup target PEP */
    pep = mxr_cm_lookup_pep(&pkt->target);
    if (!pep) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "Cannot find PEP\n");
        return -FI_EINVAL;
    }

    eq = pep->eq;
    if (!eq) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "Cannot find EQ\n");
        return -FI_EINVAL;
    }

#if 0
    /* Lookup EQ associated with PEP target address */
    eq = lookup_local_eq(&pkt->target);
    if (!eq) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "Cannot find EQ\n");
        return -FI_EINVAL;
    }

    if (!eq->pep) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "EQ not bound to PEP\n");
        return -FI_EINVAL;
    }
#endif

    /* Register remote CM */
    ret = mxr_cm_register_remote_cm(&pkt->source, &pkt->name, pkt->namelen);
    if (ret) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "Cannot register CM: %d\n", ret);
        return ret;
    }

    /* Store remote EP address in new fi_info */
    info = fi_dupinfo(eq->pep->info);
    if (!info) {
        return -FI_ENOMEM;
    }
    if (info->dest_addrlen < sizeof pkt->source) {
        if (info->dest_addr) {
            free(info->dest_addr);
        }
        info->dest_addr = calloc(1, sizeof pkt->source);
        if (!info->dest_addr) {
            ret = -FI_ENOMEM;
            goto freeinfo;
        }
    }
    memcpy(info->dest_addr, (void*)&pkt->source, sizeof pkt->source);
    info->dest_addrlen = sizeof pkt->source;

    /* info->src_addr should be the same as the PEP's == pkt->target */
    if (info->src_addrlen < sizeof pkt->target) {
        if (info->src_addr) {
            free(info->src_addr);
        }
        info->src_addr = calloc(1, sizeof pkt->target);
        if (!info->src_addr) {
            ret = -FI_ENOMEM;
            goto freeinfo;
        }
    }
    memcpy(info->src_addr, (void*)&pkt->target, sizeof pkt->target);
    info->src_addrlen = sizeof pkt->target;

#if 0
    /* Store local EP address; set port to 0 as this will be a new EP */
    info->src_addr = calloc(1, sizeof pkt->target);
    if (!info->src_addr) {
        ret = -FI_ENOMEM;
        goto freeinfo;
    }
    memcpy(info->src_addr, (void*)&pkt->target, sizeof pkt->target);
    info->src_addrlen = sizeof pkt->target;
    mxr_cm_set_port((struct sockaddr_in*)info->src_addr, 0);
#endif

    /* Enqueue new cm entry */
    eqe = (struct fi_eq_cm_entry *)&pkt->eqe_buf;
    eqe->fid = &eq->pep->pep_fid.fid;
    eqe->info = info;

    len = sizeof *eqe + pkt->cm_datalen;

    ret = fi_eq_write(eq->util_eq, FI_CONNREQ, eqe, len, 0);
    if (ret != len) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "Cannot enqueue entry: %d\n", ret);
        goto freeinfo;
    }

    return 0;
freeinfo:
    fi_freeinfo(info);
    return ret;
}

ssize_t process_connresp(struct mxr_fid_domain *mxr_domain,
        struct mxr_conn_pkt *pkt)
{
    /*
     * target: local EP address
     * source: remote EP address
     * name: remote EP name
     */
    ssize_t ret;
    size_t len;
    struct fi_eq_cm_entry *eqe;
    struct mxr_fid_ep *ep = NULL;
    struct mxr_fid_eq *eq = NULL;

    /* Lookup EP associated with target address */
#if 0
    ep = lookup_local_ep(&pkt->target);
#endif
    ep = mxr_cm_lookup_ep(&pkt->target, &pkt->source);
    if (!ep) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "Cannot find EP\n");
        return -FI_EINVAL;
    }

    eq = ep->eq;
    if (!eq) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "No bound EQ\n");
        return -FI_EINVAL;
    }

#if 0
    /* Register remote CM */
    ret = mxr_cm_register_remote_cm(&pkt->source, &pkt->cm_name,
                                    pkt->cm_namelen);
    if (ret) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "Cannot register CM: %d\n", ret);
        return ret;
    }
#endif

    /* Insert remote EP name into AV */
    if (pkt->namelen == 0) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "No remote EP name received\n");
        return -FI_EINVAL;
    }

    if (ep->peer_fi_addr != FI_ADDR_UNSPEC) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "EP is already connected\n");
        return -FI_EINVAL;
    }

    ret = fi_av_insert(mxr_domain->rd_av, pkt->name, 1,
                       &ep->peer_fi_addr, 0, NULL);
    if (ret != 1) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "fi_av_insert returned %d\n", ret);
        return ret;
    }

    /* TODO: do we have to send the cm_data back? */
    ret = mxr_cm_send(MXR_CONN_ACK, ep, &pkt->source, NULL, 0);
    if (ret) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "fi_send returned %d\n", ret);
        return ret;
    }

    /* Enqueue new CM entry */
    /* TODO: Shouldn't this be done after the Send Ack completion? */
    eqe = (struct fi_eq_cm_entry *)&pkt->eqe_buf;
    eqe->fid = &ep->ep_fid.fid;

    len = sizeof *eqe + pkt->cm_datalen;

    ret = fi_eq_write(eq->util_eq, FI_CONNECTED, eqe, len, 0);
    if (ret != len) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "Cannot enqueue entry: %d\n", ret);
        return ret;
    }

    return 0;
}

ssize_t process_connack(struct mxr_fid_domain *mxr_domain,
        struct mxr_conn_pkt *pkt)
{
    /*
     * target: local EP address
     * source: remote EP address
     * name: remote EP name
     */
    ssize_t ret;
    size_t len;
    struct fi_eq_cm_entry *eqe;
    struct mxr_fid_ep *ep = NULL;
    struct mxr_fid_eq *eq = NULL;

    /* Lookup EP associated with target address */
#if 0
    ep = lookup_local_ep(&pkt->target);
#endif
    ep = mxr_cm_lookup_ep(&pkt->target, &pkt->source);
    if (!ep) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "Cannot find EP\n");
        return -FI_EINVAL;
    }

#if 0
    /* Lookup EQ associated with target address */
    eq = lookup_local_eq(&pkt->target);
#endif
    eq = ep->eq;
    if (!eq) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "Cannot find EQ\n");
        return -FI_EINVAL;
    }

    /* Insert remote EP name into AV */
    if (pkt->namelen == 0) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "No remote EP name received\n");
        return -FI_EINVAL;
    }

    if (ep->peer_fi_addr != FI_ADDR_UNSPEC) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "EP is already connected\n");
        return -FI_EINVAL;
    }

    ret = fi_av_insert(mxr_domain->rd_av, pkt->name, 1,
                       &ep->peer_fi_addr, 0, NULL);
    if (ret != 1) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "fi_av_insert returned %d\n", ret);
        return ret;
    }

    /* Enqueue new CM entry */
    eqe = (struct fi_eq_cm_entry *)&pkt->eqe_buf;
    eqe->fid = &ep->ep_fid.fid;

    len = sizeof *eqe + pkt->cm_datalen;

    ret = fi_eq_write(eq->util_eq, FI_CONNECTED, eqe, len, 0);
    if (ret != len) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "Cannot enqueue entry: %d\n", ret);
        return ret;
    }

    return 0;
}

ssize_t process_connrej(struct mxr_fid_domain *mxr_domain,
        struct mxr_conn_pkt *pkt)
{
    /*
     * target: local EP address
     * source: remote PEP address
     * name: empty 
     */
    struct mxr_fid_eq *eq = NULL;

    /* Lookup EQ associated with target address */
    eq = lookup_local_eq(&pkt->target);
    if (!eq) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "Cannot find EQ\n");
        return -FI_EINVAL;
    }

    return -FI_ENOSYS;
}

ssize_t mxr_cm_progress(struct mxr_fid_domain *mxr_domain)
{
    ssize_t ret;
    ssize_t count;
    struct mxr_conn_buf *cm_buf;
    struct fid_cq *rd_cq = mxr_domain->cm_rd_cq;
    struct fi_cq_tagged_entry wc = { 0 };

    count = 0;
    while (1) {
        ret = fi_cq_read(rd_cq, (void*)&wc, 1);
        if (ret > 0) {
            FI_INFO(&mxr_prov, FI_LOG_FABRIC, "CM EQ completion 0x%x\n",
                    wc.flags);
            cm_buf = TO_MXR_CONN_BUF(wc.op_context);
            if (wc.flags & FI_SEND) {
                /* TODO: Process conn_resp and conn_ack sends --> events */
                /* conn_req and conn_rej sends don't create any events */
                dlist_remove(&cm_buf->list_entry);
                free(cm_buf);
                continue;
            }
            switch(cm_buf->data.type) {
            case MXR_CONN_REQ:
                FI_INFO(&mxr_prov, FI_LOG_FABRIC, "Got a MXR_CONN_REQ!\n");
                ret = process_connreq(mxr_domain, &cm_buf->data);
                if (ret) {
                    FI_WARN(&mxr_prov, FI_LOG_FABRIC,
                            "Couldn't process connection request: %d\n", ret);
                    return -FI_EOTHER;
                }
                break;
            case MXR_CONN_RESP:
                FI_INFO(&mxr_prov, FI_LOG_FABRIC, "Got a MXR_CONN_RESP!\n");
                ret = process_connresp(mxr_domain, &cm_buf->data);
                if (ret) {
                    FI_WARN(&mxr_prov, FI_LOG_FABRIC,
                            "Couldn't process connection response: %d\n", ret);
                    return -FI_EOTHER;
                }
                break;
            case MXR_CONN_ACK:
                FI_INFO(&mxr_prov, FI_LOG_FABRIC, "Got a MXR_CONN_ACK!\n");
                ret = process_connack(mxr_domain, &cm_buf->data);
                if (ret) {
                    FI_WARN(&mxr_prov, FI_LOG_FABRIC,
                            "Couldn't process connection ack: %d\n", ret);
                    return -FI_EOTHER;
                }
                break;
            case MXR_CONN_REJ:
                FI_INFO(&mxr_prov, FI_LOG_FABRIC, "Got a MXR_CONN_REJ!\n");
                ret = process_connrej(mxr_domain, &cm_buf->data);
                if (ret) {
                    FI_WARN(&mxr_prov, FI_LOG_FABRIC,
                            "Couldn't process connection rej: %d\n", ret);
                    return -FI_EOTHER;
                }
                break;
            default:
                FI_WARN(&mxr_prov, FI_LOG_FABRIC, "Unknown CM msg type: %d\n",
                        cm_buf->data.type);
                return -FI_EINVAL;
            }

            /* Re-post RX cm_buf */
            ret = fi_recv(mxr_domain->cm_rd_ep, &cm_buf->data,
                          sizeof cm_buf->data, NULL,
                          FI_ADDR_UNSPEC, (void*)&cm_buf->ctx);
            if (ret) {
                FI_WARN(&mxr_prov, FI_LOG_FABRIC,
                        "Couldn't re-post CM buffer\n", ret);
                return -FI_EOTHER;
            }

            /* Increment number of processed entries */
            count++;
        } else if (-FI_EAGAIN == ret) {
            /* Done progressing */
            break;
        } else if (-FI_EAVAIL == ret) {
            /* TODO: Retrieve error? */
            FI_WARN(&mxr_prov, FI_LOG_FABRIC, "Unexpected CM EQ error\n");
            return -FI_EOTHER;
        } else {
            FI_WARN(&mxr_prov, FI_LOG_FABRIC, "Unknown CM EQ error %d\n", ret);
            return -FI_EOTHER;
        }
    }

    return count;
}

struct fi_ops_cm mxr_ops_cm = {
    .size = sizeof(struct fi_ops_cm),
    .setname = mxr_setname,
    .getname = mxr_getname,
    .getpeer = mxr_getpeer,
    .connect = mxr_connect,
    .listen = mxr_listen,
    .accept = mxr_accept,
    .reject = mxr_reject,
    .shutdown = mxr_shutdown
};

