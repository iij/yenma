/*
 * Copyright (c) 2014 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <sys/types.h>
#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "loghandler.h"
#include "dnsresolv.h"
#include "resolverpool.h"

struct ResolverPool {
    pthread_mutex_t pool_lock;
    size_t poolednum;
    size_t maxslotnum;
    DnsResolver_initializer *initializer;
    const char *initfile;
    int timeout_overwrite;
    int retry_count_overwrite;
    DnsResolver *slot[];
};

ResolverPool *
ResolverPool_new(DnsResolver_initializer *initializer, const char *initfile, size_t slotnum,
                 int timeout_overwrite, int retry_count_overwrite)
{
    assert(NULL != initializer);

    size_t memsize = sizeof(ResolverPool) + sizeof(DnsResolver *) * slotnum;
    ResolverPool *self = (ResolverPool *) malloc(memsize);
    if (NULL == self) {
        return NULL;
    }   // end if
    memset(self, 0, memsize);

    pthread_mutex_init(&self->pool_lock, NULL);
    self->initializer = initializer;
    self->initfile = initfile;
    self->timeout_overwrite = timeout_overwrite;
    self->retry_count_overwrite = retry_count_overwrite;
    self->maxslotnum = slotnum;
    self->poolednum = 0;
    return self;
}   // end function: ResolverPool_new

DnsResolver *
ResolverPool_acquire(ResolverPool *self)
{
    int ret = pthread_mutex_lock(&self->pool_lock);
    if (0 != ret) {
        LogError("pthread_mutex_lock failed: errno=%s", strerror(ret));
        return NULL;
    }   // end if

    DnsResolver *resolver = NULL;
    if (0 < self->poolednum) {
        --self->poolednum;
        resolver = self->slot[self->poolednum];
        self->slot[self->poolednum] = NULL;
    }   // end if

    ret = pthread_mutex_unlock(&self->pool_lock);
    if (0 != ret) {
        LogError("pthread_mutex_unlock failed: errno=%s", strerror(ret));
    }   // end if

    if (NULL == resolver) {
        resolver = self->initializer(self->initfile);
        if (NULL != resolver) {
            if (0 <= self->timeout_overwrite) {
                DnsResolver_setTimeout(resolver, (time_t) self->timeout_overwrite);
            }   // end if
            if (0 <= self->retry_count_overwrite) {
                DnsResolver_setRetryCount(resolver, self->retry_count_overwrite);
            }   // end if
        }   // end if
    }   // end if

    return resolver;
}   // end function: ResolverPool_acquire

void
ResolverPool_release(ResolverPool *self, DnsResolver *resolver)
{
    int ret = pthread_mutex_lock(&self->pool_lock);
    if (0 != ret) {
        LogError("pthread_mutex_lock failed: errno=%s", strerror(ret));
        return;
    }   // end if

    if (self->poolednum < self->maxslotnum) {
        self->slot[self->poolednum] = resolver;
        ++self->poolednum;
        resolver = NULL;
    }   // end if

    ret = pthread_mutex_unlock(&self->pool_lock);
    if (0 != ret) {
        LogError("pthread_mutex_unlock failed: errno=%s", strerror(ret));
    }   // end if

    DnsResolver_free(resolver);
}   // end function: ResolverPool_release

void
ResolverPool_free(ResolverPool *self)
{
    if (NULL == self) {
        return;
    }   // end if

    pthread_mutex_destroy(&self->pool_lock);
    for (size_t i = 0; i < self->poolednum; ++i) {
        DnsResolver_free(self->slot[i]);
    }   // end for
    free(self);
}   // end function: ResolverPool_free
