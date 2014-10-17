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

#ifndef __DNS_RESOLV_H__
#define __DNS_RESOLV_H__

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "loghandler.h"

#ifdef __cplusplus
extern "C" {
#endif

enum dns_stat_t {
    DNS_STAT_NOERROR = 0,
    DNS_STAT_FORMERR = 1,
    DNS_STAT_SERVFAIL = 2,
    DNS_STAT_NXDOMAIN = 3,
    DNS_STAT_NOTIMPL = 4,
    DNS_STAT_REFUSED = 5,
    DNS_STAT_YXDOMAIN = 6,
    DNS_STAT_YXRRSET = 7,
    DNS_STAT_NXRRSET = 8,
    DNS_STAT_NOTAUTH = 9,
    DNS_STAT_NOTZONE = 10,
    DNS_STAT_RESERVED11 = 11,
    DNS_STAT_RESERVED12 = 12,
    DNS_STAT_RESERVED13 = 13,
    DNS_STAT_RESERVED14 = 14,
    DNS_STAT_RESERVED15 = 15,
    DNS_STAT_SYSTEM = 0x100,
    DNS_STAT_NODATA,    // RCODE=0, ANCOUNT=0
    DNS_STAT_NOVALIDANSWER, // no matching records of the type that has been queried for
    DNS_STAT_NOMEMORY,
    DNS_STAT_RESOLVER,
    DNS_STAT_RESOLVER_INTERNAL,
    DNS_STAT_BADREQUEST,
};
typedef enum dns_stat_t dns_stat_t;

typedef struct DnsAResponse {
    size_t num;
    struct in_addr addr[];
} DnsAResponse;

typedef struct DnsAaaaResponse {
    size_t num;
    struct in6_addr addr[];
} DnsAaaaResponse;

typedef struct DnsPtrResponse {
    size_t num;
    char *domain[];
} DnsPtrResponse;

typedef struct DnsTxtResponse {
    size_t num;
    char *data[];
} DnsTxtResponse;
typedef struct DnsTxtResponse DnsSpfResponse;

typedef struct DnsMxResponse {
    size_t num;
    struct mxentry {
        uint16_t preference;
        char domain[];
    } *exchange[];
} DnsMxResponse;

typedef struct DnsResolver DnsResolver;
typedef DnsResolver *(DnsResolver_initializer)(const char *initfile);

extern void DnsAResponse_free(DnsAResponse *self);
extern void DnsAaaaResponse_free(DnsAaaaResponse *self);
extern void DnsMxResponse_free(DnsMxResponse *self);
extern void DnsTxtResponse_free(DnsTxtResponse *self);
extern void DnsSpfResponse_free(DnsSpfResponse *self);
extern void DnsPtrResponse_free(DnsPtrResponse *self);
extern const char *DnsResolver_symbolizeErrorCode(dns_stat_t status);
extern DnsResolver *DnsResolver_new(const char *modname, const char *initfile);
extern DnsResolver_initializer *DnsResolver_lookupInitializer(const char *modname);

struct DnsResolver_vtbl {
    const char *name;
    void (*free)(DnsResolver *self);
    const char *(*getErrorSymbol)(const DnsResolver *self);
    void (*setTimeout)(const DnsResolver *self, time_t timeout);
    void (*setRetryCount)(const DnsResolver *self, int retry);
    dns_stat_t (*lookupA)(DnsResolver *self, const char *domain, DnsAResponse **resp);
    dns_stat_t (*lookupAaaa)(DnsResolver *self, const char *domain, DnsAaaaResponse **resp);
    dns_stat_t (*lookupMx)(DnsResolver *self, const char *domain, DnsMxResponse **resp);
    dns_stat_t (*lookupTxt)(DnsResolver *self, const char *domain, DnsTxtResponse **resp);
    dns_stat_t (*lookupSpf)(DnsResolver *self, const char *domain, DnsSpfResponse **resp);
    dns_stat_t (*lookupPtr)(DnsResolver *self, sa_family_t af, const void *addr, DnsPtrResponse **resp);
};

#define DnsResolver_name(_resolver) ((_resolver)->vtbl->name)
#define DnsResolver_free(_resolver) \
    do { \
        if (NULL != (_resolver)) { \
            (_resolver)->vtbl->free(_resolver); \
        } \
    } while (0)
#define DnsResolver_getErrorSymbol(_resolver) ((_resolver)->vtbl->getErrorSymbol(_resolver))
#define DnsResolver_setTimeout(_resolver, _timeout) ((_resolver)->vtbl->setTimeout(_resolver, _timeout))
#define DnsResolver_setRetryCount(_resolver, _retry) ((_resolver)->vtbl->setRetryCount(_resolver, _retry))
#define DnsResolver_lookupA(_resolver, _domain, _resp) ((_resolver)->vtbl->lookupA(_resolver, _domain, _resp))
#define DnsResolver_lookupAaaa(_resolver, _domain, _resp) ((_resolver)->vtbl->lookupAaaa(_resolver, _domain, _resp))
#define DnsResolver_lookupMx(_resolver, _domain, _resp) ((_resolver)->vtbl->lookupMx(_resolver, _domain, _resp))
#define DnsResolver_lookupTxt(_resolver, _domain, _resp) ((_resolver)->vtbl->lookupTxt(_resolver, _domain, _resp))
#define DnsResolver_lookupSpf(_resolver, _domain, _resp) ((_resolver)->vtbl->lookupSpf(_resolver, _domain, _resp))
#define DnsResolver_lookupPtr(_resolver, _af, _addr, _resp) ((_resolver)->vtbl->lookupPtr(_resolver, _af, _addr, _resp))

#define DnsResolver_MEMBER              \
    const struct DnsResolver_vtbl *vtbl

struct DnsResolver {
    DnsResolver_MEMBER;
};

#define LogDnsError(_rrtype, _qname, _event, _errmsg) LogInfo("DNS lookup failure (" _event "): rrtype=" _rrtype ", qname=%s, error=%s", _qname, _errmsg)

#ifdef __cplusplus
}
#endif

#endif /* __DNS_RESOLV_H__ */
