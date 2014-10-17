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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <sys/types.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <netinet/in.h>
#include <arpa/nameser.h>

#include "stdaux.h"
#include "keywordmap.h"
#include "dnsresolv.h"
#include "dnsresolv_internal.h"

#if defined(HAVE_LIBBIND) || defined(USE_LIBRESOLV)
#include "bindresolver.h"
#endif
#if defined(HAVE_LIBLDNS)
#include "ldnsresolver.h"
#endif

void
DnsAResponse_free(DnsAResponse *self)
{
    free(self);
}   // end function: DnsAResponse_free

void
DnsAaaaResponse_free(DnsAaaaResponse *self)
{
    free(self);
}   // end function: DnsAaaaResponse_free

void
DnsMxResponse_free(DnsMxResponse *self)
{
    if (NULL == self) {
        return;
    }   // end if

    for (size_t n = 0; n < self->num; ++n) {
        free(self->exchange[n]);
    }   // end for
    free(self);
}   // end function: DnsMxResponse_free

void
DnsTxtResponse_free(DnsTxtResponse *self)
{
    if (NULL == self) {
        return;
    }   // end if

    for (size_t n = 0; n < self->num; ++n) {
        free(self->data[n]);
    }   // end for
    free(self);
}   // end function: DnsTxtResponse_free

void
DnsSpfResponse_free(DnsSpfResponse *self)
{
    DnsTxtResponse_free(self);
}   // end function: DnsSpfResponse_free

void
DnsPtrResponse_free(DnsPtrResponse *self)
{
    if (NULL == self) {
        return;
    }   // end if

    for (size_t n = 0; n < self->num; ++n) {
        free(self->domain[n]);
    }   // end for
    free(self);
}   // end function: DnsPtrResponse_free

const char *
DnsResolver_symbolizeErrorCode(dns_stat_t status)
{
    static const KeywordMap dns_stat_tbl[] = {
        {"NOERROR", DNS_STAT_NOERROR},
        {"FORMERR", DNS_STAT_FORMERR},
        {"SERVFAIL", DNS_STAT_SERVFAIL},
        {"NXDOMAIN", DNS_STAT_NXDOMAIN},
        {"NOTIMPL", DNS_STAT_NOTIMPL},
        {"REFUSED", DNS_STAT_REFUSED},
        {"YXDOMAIN", DNS_STAT_YXDOMAIN},
        {"YXRRSET", DNS_STAT_YXRRSET},
        {"NXRRSET", DNS_STAT_NXRRSET},
        {"NOTAUTH", DNS_STAT_NOTAUTH},
        {"NOTZONE", DNS_STAT_NOTZONE},
        {"RESERVED11", DNS_STAT_RESERVED11},
        {"RESERVED12", DNS_STAT_RESERVED12},
        {"RESERVED13", DNS_STAT_RESERVED13},
        {"RESERVED14", DNS_STAT_RESERVED14},
        {"RESERVED15", DNS_STAT_RESERVED15},
        {"SYSTEM", DNS_STAT_SYSTEM},
        {"NODATA", DNS_STAT_NODATA},
        {"NOVALIDANSWER", DNS_STAT_NOVALIDANSWER},
        {"NOMEMORY", DNS_STAT_NOMEMORY},
        {"RESOLVER_ERROR", DNS_STAT_RESOLVER},
        {"RESOLVER_INTERNAL", DNS_STAT_RESOLVER_INTERNAL},
        {"BADREQUEST", DNS_STAT_BADREQUEST},
        {NULL, 0},  // sentinel
    };
    return KeywordMap_lookupByValue(dns_stat_tbl, status);
}   // end function: DnsResolver_symbolizeErrorCode

/*
 * @attention the size of buflen must be DNS_IP4_REVENT_MAXLEN bytes or larger
 */
bool
DnsResolver_expandReverseEntry4(const struct in_addr *addr4, char *buf, size_t buflen)
{
    const unsigned char *rawaddr = (const unsigned char *) addr4;
    int ret =
        snprintf(buf, buflen, "%hhu.%hhu.%hhu.%hhu." DNS_IP4_REVENT_SUFFIX, rawaddr[3], rawaddr[2],
                 rawaddr[1], rawaddr[0]);
    return bool_cast(ret < (int) buflen);
}   // end function: DnsResolver_expandReverseEntry4

/*
 * Convert an integer between 0 and 15 to a corresponding ascii character between '0' and 'f'.
 * @attention If an integer is less than 0 or greater than 15, the results are undefined.
 */
static char
xtoa(unsigned char p)
{
    return p < 0xa ? p + '0' : p + 'a' - 0xa;
}   // end function: xtoa

/*
 * @attention the size of buflen must be DNS_IP6_REVENT_MAXLEN bytes or larger
 */
bool
DnsResolver_expandReverseEntry6(const struct in6_addr *addr6, char *buf, size_t buflen)
{
    if (buflen < DNS_IP6_REVENT_MAXLEN) {
        return false;
    }   // end if
    const uint8_t *rawaddr_head = (const uint8_t *) addr6;
    const uint8_t *rawaddr_tail = rawaddr_head + NS_IN6ADDRSZ;
    char *bufp = buf;
    for (const uint8_t *p = rawaddr_tail - 1; rawaddr_head <= p; --p) {
        *(bufp++) = xtoa(*p & 0x0f);
        *(bufp++) = '.';
        *(bufp++) = xtoa((*p & 0xf0) >> 4);
        *(bufp++) = '.';
    }   // end for
    memcpy(bufp, DNS_IP6_REVENT_SUFFIX, sizeof(DNS_IP6_REVENT_SUFFIX)); // copy suffix including NULL terminator
    return true;
}   // end function: DnsResolver_expandReverseEntry6

typedef struct DnsResolverInitilizerMap {
    const char *modname;
    DnsResolver_initializer *initializer;
} DnsResolverInitilizerMap;

static const DnsResolverInitilizerMap resolver_initializer_table[] = {
#if defined(HAVE_LIBLDNS)
    {"ldns", LdnsResolver_new},
#endif
#if defined(HAVE_LIBBIND)
    {"bind", BindResolver_new},
    {"libbind", BindResolver_new},
#endif
#if defined(USE_LIBRESOLV)
    {"resolv", BindResolver_new},
#endif
    {NULL, NULL},   // sentinel
};

DnsResolver_initializer *
DnsResolver_lookupInitializer(const char *modname)
{
    const DnsResolverInitilizerMap *p;
    for (p = resolver_initializer_table; NULL != p->modname; ++p) {
        if (NULL == modname || 0 == strcasecmp(p->modname, modname)) {
            return p->initializer;
        }   // end if
    }   // end for
    return NULL;
}   // end function: DnsResolver_lookupInitializer

DnsResolver *
DnsResolver_new(const char *modname, const char *initfile)
{
    DnsResolver_initializer *initializer = DnsResolver_lookupInitializer(modname);
    return NULL != initializer ? initializer(initfile) : NULL;
}   // end function: DnsResolver_new
