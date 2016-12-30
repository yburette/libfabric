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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "mxr.h"

#define PORT "8484"
#define MAXBUFLEN 100

struct mxr_thread_data {
    size_t namelen;
    char name[FI_NAME_MAX];
};

static void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

static void cleanup_nameserver(void *data)
{
    FI_INFO(&mxr_prov, FI_LOG_FABRIC, "closing socket\n");
    close((uintptr_t)data);
}

static void *run_nameserver(void *data)
{
    int numbytes;
    struct addrinfo hints, *servinfo, *p;
    int rv;
    long ret = 0;
    struct sockaddr_storage their_addr;
    struct mxr_thread_data *tdata = data;
    socklen_t addr_len;
    char s[INET6_ADDRSTRLEN];
    int sockfd;

    FI_INFO(&mxr_prov, FI_LOG_FABRIC, "nameserver thread started\n");
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "getaddrinfo failed: %s\n",
                gai_strerror(rv));
        ret=-1;
        goto exit;
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                             p->ai_protocol)) == -1) {
            perror("listener: socket");
            continue;
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("listener: bind");
            continue;
        }

        break;
    }

    if (p == NULL) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "failed to bind socket\n");
        ret=-2;
        goto exit;
    }

    freeaddrinfo(servinfo);

    FI_INFO(&mxr_prov, FI_LOG_FABRIC, "nameserver thread ready\n");

    pthread_cleanup_push(cleanup_nameserver, (void*)(uintptr_t)sockfd);

    while (1) {
        addr_len = sizeof their_addr;
        if ((numbytes = recvfrom(sockfd, NULL, 0, 0,
                        (struct sockaddr*)&their_addr, &addr_len)) == -1) {
            perror("recvfrom");
            ret=-3;
            goto closefd;
        }

        FI_INFO(&mxr_prov, FI_LOG_FABRIC,
                "nameserver got a request from %s\n",
                inet_ntop(their_addr.ss_family,
                get_in_addr((struct sockaddr *)&their_addr),
                s, sizeof s));

        if ((numbytes = sendto(sockfd, tdata->name, tdata->namelen, 0,
                        (struct sockaddr*)&their_addr, addr_len)) == -1) {
            perror("listener: sendto");
            ret=-4;
            goto closefd;
        }
    }
closefd:
    pthread_cleanup_pop(1);
exit:
    FI_INFO(&mxr_prov, FI_LOG_FABRIC, "nameserver thread exiting\n");
    pthread_exit((void*)ret);
}

int mxr_start_nameserver(struct mxr_fid_pep *mxr_pep)
{
    pthread_attr_t attr;
    struct mxr_thread_data *tdata;
    int ret;

    tdata = calloc(1, sizeof *tdata);
    if (!tdata) {
        return -FI_ENOMEM;
    }

    tdata->namelen = FI_NAME_MAX;

    ret = fi_getname((fid_t)mxr_pep->ctrl_ep, tdata->name, &tdata->namelen);
    if (ret) {
        goto freedata;
    }

    mxr_pep->tdata = tdata;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    if ((ret = pthread_create(&mxr_pep->nameserver_thread, &attr,
                    run_nameserver, (void*)tdata)) != 0) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "pthread_create failed: %d\n", ret);
        ret = -FI_EOTHER;
        goto freedata;
    }
    pthread_attr_destroy(&attr);

    return 0;
freedata:
    free(tdata);
    return ret;
}

int mxr_stop_nameserver(struct mxr_fid_pep *mxr_pep)
{
    void *status;
    int rv;

    if (pthread_equal(mxr_pep->nameserver_thread, pthread_self())) {
        return -FI_EINVAL;
    }

    if ((rv = pthread_cancel(mxr_pep->nameserver_thread)) != 0) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "pthread_cancel failed: %d\n", rv);
    }

    if ((rv = pthread_join(mxr_pep->nameserver_thread, &status)) != 0) {
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "pthread_join failed: %d\n", rv);
        return -FI_EINVAL;
    }

    free(mxr_pep->tdata);

    switch((long)status) {
    case 0:
    case -1:
        FI_INFO(&mxr_prov, FI_LOG_FABRIC, "thread exited successfully\n");
        break;
    default:
        FI_WARN(&mxr_prov, FI_LOG_FABRIC, "thread exited with an error: %ld\n",
                (long)status);
        return -FI_EOTHER;
    }

    return 0;
}
