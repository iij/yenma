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

#ifndef __RESOLVER_POOL_H__
#define __RESOLVER_POOL_H__

#include <sys/types.h>
#include "dnsresolv.h"

typedef struct ResolverPool ResolverPool;

extern ResolverPool *ResolverPool_new(DnsResolver_initializer *initializer, const char *initfile,
                                      size_t slotnum, int timeout_overwrite,
                                      int retry_count_overwrite);
extern DnsResolver *ResolverPool_acquire(ResolverPool *self);
extern void ResolverPool_release(ResolverPool *self, DnsResolver *resolver);
extern void ResolverPool_free(ResolverPool *self);

#endif /* __RESOLVER_POOL_H__ */
