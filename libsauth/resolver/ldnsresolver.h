/*
 * Copyright (c) 2014,2015 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifndef __LDNS_RESOLVER_H__
#define __LDNS_RESOLVER_H__

#include "dnsresolv.h"

#ifdef __cplusplus
extern "C" {
#endif

extern DnsResolver *LdnsResolver_new(const char *initfile);

#ifdef __cplusplus
}
#endif

#endif /* __LDNS_RESOLVER_H__ */
