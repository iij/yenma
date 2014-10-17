/*
 * Copyright (c) 2008-2014 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifndef __DNSRESOLV_INTERNAL_H__
#define __DNSRESOLV_INTERNAL_H__

#include <stdbool.h>
#include <stddef.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DNS_IP4_REVENT_SUFFIX "in-addr.arpa."
#define DNS_IP6_REVENT_SUFFIX "ip6.arpa."

#define DNS_IP4_REVENT_MAXLEN sizeof("123.456.789.012." DNS_IP4_REVENT_SUFFIX)
#define DNS_IP6_REVENT_MAXLEN sizeof("0.1.2.3.4.5.6.7.8.9.a.b.c.d.e.f.0.1.2.3.4.5.6.7.8.9.a.b.c.d.e.f." DNS_IP6_REVENT_SUFFIX)

extern bool DnsResolver_expandReverseEntry4(const struct in_addr *addr4, char *buf, size_t buflen);
extern bool DnsResolver_expandReverseEntry6(const struct in6_addr *addr6, char *buf, size_t buflen);

#ifdef __cplusplus
}
#endif

#endif /* __DNSRESOLV_INTERNAL_H__ */
