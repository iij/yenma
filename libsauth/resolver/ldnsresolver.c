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

// ldns-1.6.0 or higher is required

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <arpa/nameser.h>
#include <ldns/ldns.h>

#include "stdaux.h"
#include "ptrop.h"
#include "dnsresolv.h"
#include "dnsresolv_internal.h"
#include "ldnsresolver.h"

#ifndef _PATH_RESCONF
#define _PATH_RESCONF  "/etc/resolv.conf"
#endif

typedef struct LdnsResolver {
    DnsResolver_MEMBER;
    ldns_resolver *res;
    dns_stat_t status;
    ldns_status res_stat;
} LdnsResolver;

static dns_stat_t
LdnsResolver_rcode2statcode(ldns_pkt_rcode rcode)
{
    switch (rcode) {
    case LDNS_RCODE_NOERROR:
        return DNS_STAT_NOERROR;
    case LDNS_RCODE_FORMERR:
        return DNS_STAT_FORMERR;
    case LDNS_RCODE_SERVFAIL:
        return DNS_STAT_SERVFAIL;
    case LDNS_RCODE_NXDOMAIN:
        return DNS_STAT_NXDOMAIN;
    case LDNS_RCODE_NOTIMPL:
        return DNS_STAT_NOTIMPL;
    case LDNS_RCODE_REFUSED:
        return DNS_STAT_REFUSED;
    case LDNS_RCODE_YXDOMAIN:
        return DNS_STAT_YXDOMAIN;
    case LDNS_RCODE_YXRRSET:
        return DNS_STAT_YXRRSET;
    case LDNS_RCODE_NXRRSET:
        return DNS_STAT_NXRRSET;
    case LDNS_RCODE_NOTAUTH:
        return DNS_STAT_NOTAUTH;
    case LDNS_RCODE_NOTZONE:
        return DNS_STAT_NOTZONE;
    default:
        return DNS_STAT_RESOLVER_INTERNAL;
    }   // end switch

}   // end function: LdnsResolver_rcode2statcode

static dns_stat_t
LdnsResolver_setRcode(LdnsResolver *self, ldns_pkt_rcode rcode)
{
    self->status = LdnsResolver_rcode2statcode(rcode);
    return self->status;    // for caller's convenience
}   // end function: LdnsResolver_setRcode

static dns_stat_t
LdnsResolver_setError(LdnsResolver *self, dns_stat_t status)
{
    self->status = status;
    return self->status;    // for caller's convenience
}   // end function: LdnsResolver_setError

static dns_stat_t
LdnsResolver_setResolverError(LdnsResolver *self, ldns_status status)
{
    self->status = DNS_STAT_RESOLVER;
    self->res_stat = status;
    return self->status;    // for caller's convenience
}   // end function: LdnsResolver_setResolverError

static void
LdnsResolver_resetErrorState(LdnsResolver *self)
{
    self->status = DNS_STAT_NOERROR;
    self->res_stat = LDNS_STATUS_OK;
    // reset the rtt of the nameservers marked as unreachable (LDNS_RESOLV_RTT_INF)
    for (size_t i = 0; i < ldns_resolver_nameserver_count(self->res); ++i) {
        if (LDNS_RESOLV_RTT_INF == ldns_resolver_nameserver_rtt(self->res, i)) {
            ldns_resolver_set_nameserver_rtt(self->res, i, LDNS_RESOLV_RTT_MIN);
        }   // end if
    }   // end for
}   // end function: LdnsResolver_resetErrorState

static const char *
LdnsResolver_getErrorSymbol(const DnsResolver *base)
{
    LdnsResolver *self = (LdnsResolver *) base;
    return (DNS_STAT_RESOLVER == self->status)
        ? ldns_get_errorstr_by_id(self->res_stat)
        : DnsResolver_symbolizeErrorCode(self->status);
}   // end function: LdnsResolver_getErrorSymbol

static void
LdnsResolver_setTimeout(const DnsResolver *base, time_t timeout)
{
    LdnsResolver *self = (LdnsResolver *) base;
    struct timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    ldns_resolver_set_timeout(self->res, tv);
}   // end function: LdnsResolver_setTimeout

static void
LdnsResolver_setRetryCount(const DnsResolver *base, int retry)
{
    LdnsResolver *self = (LdnsResolver *) base;
    ldns_resolver_set_retry(self->res, (uint8_t) retry);
}   // end function: LdnsResolver_setRetryCount

/*
 * throw a DNS query and receive a response of it
 * @return
 */
static dns_stat_t
LdnsResolver_query(LdnsResolver *self, const char *domain, ldns_rr_type rrtype,
                   ldns_rr_list **rrlist)
{
    LdnsResolver_resetErrorState(self);
    ldns_rdf *rdf_domain = ldns_dname_new_frm_str(domain);
    if (NULL == rdf_domain) {
        return LdnsResolver_setError(self, DNS_STAT_BADREQUEST);
    }   // end if
    ldns_pkt *packet = NULL;
    ldns_status status =
        ldns_resolver_send(&packet, self->res, rdf_domain, rrtype, LDNS_RR_CLASS_IN, LDNS_RD);
    ldns_rdf_deep_free(rdf_domain);
    if (status != LDNS_STATUS_OK) {
        return LdnsResolver_setResolverError(self, status);
    }   // end if
    if (NULL == packet) {
        return LdnsResolver_setError(self, DNS_STAT_RESOLVER_INTERNAL);
    }   // end if
    ldns_pkt_rcode rcode = ldns_pkt_get_rcode(packet);
    if (LDNS_RCODE_NOERROR != rcode) {
        ldns_pkt_free(packet);
        return LdnsResolver_setRcode(self, rcode);
    }   // end if
    *rrlist = ldns_pkt_rr_list_by_type(packet, rrtype, LDNS_SECTION_ANSWER);
    if (NULL == *rrlist) {
        ldns_pkt_free(packet);
        return LdnsResolver_setError(self, DNS_STAT_NODATA);
    }   // end if
    ldns_pkt_free(packet);
    return DNS_STAT_NOERROR;
}   // end function: LdnsResolver_query

static dns_stat_t
LdnsResolver_lookupA(DnsResolver *base, const char *domain, DnsAResponse **resp)
{
    LdnsResolver *self = (LdnsResolver *) base;
    ldns_rr_list *rrlist = NULL;
    dns_stat_t query_stat = LdnsResolver_query(self, domain, LDNS_RR_TYPE_A, &rrlist);
    if (DNS_STAT_NOERROR != query_stat) {
        return query_stat;
    }   // end if
    size_t rr_count = ldns_rr_list_rr_count(rrlist);
    if (0 == rr_count) {
        return LdnsResolver_setResolverError(self, DNS_STAT_NODATA);
    }   // end if
    DnsAResponse *respobj =
        (DnsAResponse *) malloc(sizeof(DnsAResponse) + rr_count * sizeof(struct in_addr));
    if (NULL == respobj) {
        ldns_rr_list_deep_free(rrlist);
        return LdnsResolver_setError(self, DNS_STAT_NOMEMORY);
    }   // end if
    memset(respobj, 0, sizeof(DnsAResponse) + rr_count * sizeof(struct in_addr));
    respobj->num = 0;
    for (size_t rridx = 0; rridx < rr_count; ++rridx) {
        ldns_rr *rr = ldns_rr_list_rr(rrlist, rridx);
        if (LDNS_RR_TYPE_A != ldns_rr_get_type(rr)) {
            continue;
        }   // end if
        const ldns_rdf *rdf_addr = ldns_rr_rdf(rr, 0);
        if (LDNS_RDF_TYPE_A != ldns_rdf_get_type(rdf_addr)) {
            goto formerr;
        }   // end if
        if (NS_INADDRSZ != ldns_rdf_size(rdf_addr)) {
            goto formerr;
        }   // end if
        memcpy(&respobj->addr[respobj->num], ldns_rdf_data(rdf_addr), NS_INADDRSZ);
        ++(respobj->num);
    }   // end for
    if (0 == respobj->num) {
        goto nodata;
    }   // end if
    *resp = respobj;
    ldns_rr_list_deep_free(rrlist);
    return DNS_STAT_NOERROR;

  formerr:
    ldns_rr_list_deep_free(rrlist);
    DnsAResponse_free(respobj);
    return LdnsResolver_setResolverError(self, DNS_STAT_FORMERR);

  nodata:
    ldns_rr_list_deep_free(rrlist);
    DnsAResponse_free(respobj);
    return LdnsResolver_setResolverError(self, DNS_STAT_NOVALIDANSWER);
}   // end function: LdnsResolver_lookupA

static dns_stat_t
LdnsResolver_lookupAaaa(DnsResolver *base, const char *domain, DnsAaaaResponse **resp)
{
    LdnsResolver *self = (LdnsResolver *) base;
    ldns_rr_list *rrlist = NULL;
    dns_stat_t query_stat = LdnsResolver_query(self, domain, LDNS_RR_TYPE_AAAA, &rrlist);
    if (DNS_STAT_NOERROR != query_stat) {
        return query_stat;
    }   // end if
    size_t rr_count = ldns_rr_list_rr_count(rrlist);
    if (0 == rr_count) {
        return LdnsResolver_setResolverError(self, DNS_STAT_NODATA);
    }   // end if
    DnsAaaaResponse *respobj =
        (DnsAaaaResponse *) malloc(sizeof(DnsAaaaResponse) + rr_count * sizeof(struct in6_addr));
    if (NULL == respobj) {
        ldns_rr_list_deep_free(rrlist);
        return LdnsResolver_setError(self, DNS_STAT_NOMEMORY);
    }   // end if
    memset(respobj, 0, sizeof(DnsAaaaResponse) + rr_count * sizeof(struct in6_addr));
    respobj->num = 0;
    for (size_t rridx = 0; rridx < rr_count; ++rridx) {
        ldns_rr *rr = ldns_rr_list_rr(rrlist, rridx);
        if (LDNS_RR_TYPE_AAAA != ldns_rr_get_type(rr)) {
            continue;
        }   // end if
        const ldns_rdf *rdf_addr = ldns_rr_rdf(rr, 0);
        if (LDNS_RDF_TYPE_AAAA != ldns_rdf_get_type(rdf_addr)) {
            goto formerr;
        }   // end if
        if (NS_IN6ADDRSZ != ldns_rdf_size(rdf_addr)) {
            goto formerr;
        }   // end if
        memcpy(&respobj->addr[respobj->num], ldns_rdf_data(rdf_addr), NS_IN6ADDRSZ);
        ++(respobj->num);
    }   // end for
    if (0 == respobj->num) {
        goto nodata;
    }   // end if
    *resp = respobj;
    ldns_rr_list_deep_free(rrlist);
    return DNS_STAT_NOERROR;

  formerr:
    ldns_rr_list_deep_free(rrlist);
    DnsAaaaResponse_free(respobj);
    return LdnsResolver_setResolverError(self, DNS_STAT_FORMERR);

  nodata:
    ldns_rr_list_deep_free(rrlist);
    DnsAaaaResponse_free(respobj);
    return LdnsResolver_setResolverError(self, DNS_STAT_NOVALIDANSWER);
}   // end function: LdnsResolver_lookupAaaa

static bool
LdnsResolver_expandDomainName(const ldns_rdf *rdf, char *bufp, size_t buflen)
{
    /*
     * [RFC1035] 3.3.
     * <domain-name> is a domain name represented as a series of labels, and
     * terminated by a label with zero length.
     */
    uint8_t *rdata = (uint8_t *) ldns_rdf_data(rdf);
    size_t rdflen = ldns_rdf_size(rdf);
    uint8_t *rdata_tail = rdata + rdflen;
    char *buf_tail = bufp + buflen;

    if (0 == rdflen) {
        return false;
    }   // end if

    /* special case: root label */
    if (1 == rdflen) {
        if (2 <= buflen) {
            *(bufp++) = '.';
            *(bufp++) = '\0';
            return true;
        } else {
            return false;
        }   // end if
    }   // end if

    uint8_t label_len = *(rdata++);

    // "rdata + label_len" includes the length field of the next label,
    // and "bufp + label_len" includes '.' or NULL terminator.
    while (rdata + label_len < rdata_tail && bufp + label_len < buf_tail) {
        memcpy(bufp, rdata, label_len);
        rdata += label_len;
        bufp += label_len;
        label_len = *(rdata++);
        if (0 == label_len) {
            *bufp = '\0';
            return true;
        }   // end if
        *(bufp++) = '.';
    }   // end while
    return false;
}   // end function: LdnsResolver_expandDomainName

static dns_stat_t
LdnsResolver_lookupMx(DnsResolver *base, const char *domain, DnsMxResponse **resp)
{
    LdnsResolver *self = (LdnsResolver *) base;
    ldns_rr_list *rrlist = NULL;
    dns_stat_t query_stat = LdnsResolver_query(self, domain, LDNS_RR_TYPE_MX, &rrlist);
    if (DNS_STAT_NOERROR != query_stat) {
        return query_stat;
    }   // end if
    size_t rr_count = ldns_rr_list_rr_count(rrlist);
    if (0 == rr_count) {
        return LdnsResolver_setResolverError(self, DNS_STAT_NODATA);
    }   // end if
    DnsMxResponse *respobj =
        (DnsMxResponse *) malloc(sizeof(DnsMxResponse) + rr_count * sizeof(struct mxentry *));
    if (NULL == respobj) {
        ldns_rr_list_deep_free(rrlist);
        return LdnsResolver_setError(self, DNS_STAT_NOMEMORY);
    }   // end if
    memset(respobj, 0, sizeof(DnsMxResponse) + rr_count * sizeof(struct mxentry *));
    respobj->num = 0;

    // expand compressed domain name
    for (size_t rridx = 0; rridx < rr_count; ++rridx) {
        ldns_rr *rr = ldns_rr_list_rr(rrlist, rridx);
        if (LDNS_RR_TYPE_MX != ldns_rr_get_type(rr)) {
            continue;
        }   // end if
        const ldns_rdf *rdf_pref = ldns_rr_rdf(rr, 0);
        const ldns_rdf *rdf_dname = ldns_rr_rdf(rr, 1);
        if (LDNS_RDF_TYPE_INT16 != ldns_rdf_get_type(rdf_pref) ||
            LDNS_RDF_TYPE_DNAME != ldns_rdf_get_type(rdf_dname)) {
            goto formerr;
        }   // end if

        size_t bufsize = MAX(ldns_rdf_size(rdf_dname), 2);
        size_t entrysize = sizeof(struct mxentry) + bufsize;
        // allocate memory
        struct mxentry *entryp = (struct mxentry *) malloc(entrysize);
        if (NULL == entryp) {
            goto noresource;
        }   // end if
        // concatenate
        respobj->exchange[respobj->num] = entryp;
        if (!LdnsResolver_expandDomainName(rdf_dname, entryp->domain, bufsize)) {
            goto formerr;
        }   // end if
        entryp->preference = ntohs(*(uint16_t *) ldns_rdf_data(rdf_pref));
        ++(respobj->num);
    }   // end for

    if (0 == respobj->num) {
        goto nodata;
    }   // end if
    *resp = respobj;
    ldns_rr_list_deep_free(rrlist);
    return DNS_STAT_NOERROR;

  formerr:
    ldns_rr_list_deep_free(rrlist);
    DnsMxResponse_free(respobj);
    return LdnsResolver_setResolverError(self, DNS_STAT_FORMERR);

  nodata:
    ldns_rr_list_deep_free(rrlist);
    DnsMxResponse_free(respobj);
    return LdnsResolver_setResolverError(self, DNS_STAT_NOVALIDANSWER);

  noresource:
    ldns_rr_list_deep_free(rrlist);
    DnsMxResponse_free(respobj);
    return LdnsResolver_setResolverError(self, DNS_STAT_NOMEMORY);
}   // end function: LdnsResolver_lookupMx

/**
 * @return DNS_STAT_NOERROR on success.
 */
static dns_stat_t
LdnsResolver_lookupTxtData(LdnsResolver *self, ldns_rr_type rrtype, const char *domain,
                           DnsTxtResponse **resp)
{
    ldns_rr_list *rrlist = NULL;
    dns_stat_t query_stat = LdnsResolver_query(self, domain, rrtype, &rrlist);
    if (DNS_STAT_NOERROR != query_stat) {
        return query_stat;
    }   // end if
    size_t rr_count = ldns_rr_list_rr_count(rrlist);
    if (0 == rr_count) {
        return LdnsResolver_setResolverError(self, DNS_STAT_NODATA);
    }   // end if
    DnsTxtResponse *respobj =
        (DnsTxtResponse *) malloc(sizeof(DnsTxtResponse) + rr_count * sizeof(char *));
    if (NULL == respobj) {
        ldns_rr_list_deep_free(rrlist);
        return LdnsResolver_setError(self, DNS_STAT_NOMEMORY);
    }   // end if
    memset(respobj, 0, sizeof(DnsTxtResponse) + rr_count * sizeof(char *));
    respobj->num = 0;

    // concatenate multiple rdfs for each RR
    for (size_t rridx = 0; rridx < rr_count; ++rridx) {
        ldns_rr *rr = ldns_rr_list_rr(rrlist, rridx);
        if (rrtype != ldns_rr_get_type(rr)) {
            continue;
        }   // end if
        // estimate buffer size
        size_t bufsize = 0;
        for (size_t rdfidx = 0; rdfidx < ldns_rr_rd_count(rr); ++rdfidx) {
            bufsize += ldns_rdf_size(ldns_rr_rdf(rr, rdfidx)) - 1;
        }   // end for
        ++bufsize;  // for NULL terminator
        // allocate memory
        char *bufp = (char *) malloc(bufsize);
        if (NULL == bufp) {
            goto noresource;
        }   // end if
        // concatenate
        respobj->data[respobj->num] = bufp;
        for (size_t rdfidx = 0; rdfidx < ldns_rr_rd_count(rr); ++rdfidx) {
            const ldns_rdf *rdf = ldns_rr_rdf(rr, rdfidx);
            if (LDNS_RDF_TYPE_STR != ldns_rdf_get_type(rdf)) {
                goto formerr;
            }   // end if
            const uint8_t *rdata = ldns_rdf_data(rdf);
            if (ldns_rdf_size(rdf) != (size_t) (*rdata) + 1) {
                goto formerr;
            }   // end if
            memcpy(bufp, rdata + 1, *rdata);
            bufp += (size_t) *rdata;
        }   // end for
        *bufp = '\0';   // terminate with NULL character
        ++(respobj->num);
    }   // end for

    if (0 == respobj->num) {
        goto nodata;
    }   // end if
    *resp = respobj;
    ldns_rr_list_deep_free(rrlist);
    return DNS_STAT_NOERROR;

  formerr:
    ldns_rr_list_deep_free(rrlist);
    DnsTxtResponse_free(respobj);
    return LdnsResolver_setResolverError(self, DNS_STAT_FORMERR);

  nodata:
    ldns_rr_list_deep_free(rrlist);
    DnsTxtResponse_free(respobj);
    return LdnsResolver_setResolverError(self, DNS_STAT_NOVALIDANSWER);

  noresource:
    ldns_rr_list_deep_free(rrlist);
    DnsTxtResponse_free(respobj);
    return LdnsResolver_setResolverError(self, DNS_STAT_NOMEMORY);
}   // end function: LdnsResolver_lookupTxtData

static dns_stat_t
LdnsResolver_lookupTxt(DnsResolver *base, const char *domain, DnsTxtResponse **resp)
{
    LdnsResolver *self = (LdnsResolver *) base;
    return LdnsResolver_lookupTxtData(self, LDNS_RR_TYPE_TXT, domain, resp);
}   // end function: LdnsResolver_lookupTxt

static dns_stat_t
LdnsResolver_lookupSpf(DnsResolver *base, const char *domain, DnsSpfResponse **resp)
{
    LdnsResolver *self = (LdnsResolver *) base;
    return LdnsResolver_lookupTxtData(self, LDNS_RR_TYPE_SPF, domain, resp);
}   // end function: LdnsResolver_lookupSpf

static dns_stat_t
LdnsResolver_lookupPtr(DnsResolver *base, sa_family_t sa_family, const void *addr,
                       DnsPtrResponse **resp)
{
    LdnsResolver *self = (LdnsResolver *) base;
    char domain[DNS_IP6_REVENT_MAXLEN]; // enough size for IPv6 reverse DNS entry
    switch (sa_family) {
    case AF_INET:
        if (!DnsResolver_expandReverseEntry4(addr, domain, sizeof(domain))) {
            abort();
        }   // end if
        break;
    case AF_INET6:
        if (!DnsResolver_expandReverseEntry6(addr, domain, sizeof(domain))) {
            abort();
        }   // end if
        break;
    default:
        return LdnsResolver_setError(self, DNS_STAT_BADREQUEST);
    }   // end if

    ldns_rr_list *rrlist = NULL;
    dns_stat_t query_stat = LdnsResolver_query(self, domain, LDNS_RR_TYPE_PTR, &rrlist);
    if (DNS_STAT_NOERROR != query_stat) {
        return query_stat;
    }   // end if
    size_t rr_count = ldns_rr_list_rr_count(rrlist);
    if (0 == rr_count) {
        return LdnsResolver_setResolverError(self, DNS_STAT_NODATA);
    }   // end if
    DnsPtrResponse *respobj =
        (DnsPtrResponse *) malloc(sizeof(DnsPtrResponse) + rr_count * sizeof(char *));
    if (NULL == respobj) {
        ldns_rr_list_deep_free(rrlist);
        return LdnsResolver_setError(self, DNS_STAT_NOMEMORY);
    }   // end if
    memset(respobj, 0, sizeof(DnsPtrResponse) + rr_count * sizeof(char *));
    respobj->num = 0;

    // expand compressed domain name
    for (size_t rridx = 0; rridx < rr_count; ++rridx) {
        ldns_rr *rr = ldns_rr_list_rr(rrlist, rridx);
        if (LDNS_RR_TYPE_PTR != ldns_rr_get_type(rr)) {
            continue;
        }   // end if
        const ldns_rdf *rdf = ldns_rr_rdf(rr, 0);
        if (LDNS_RDF_TYPE_DNAME != ldns_rdf_get_type(rdf)) {
            goto formerr;
        }   // end if

        size_t bufsize = MAX(ldns_rdf_size(rdf), 2);
        // allocate memory
        char *bufp = (char *) malloc(bufsize);
        if (NULL == bufp) {
            goto noresource;
        }   // end if
        // concatenate
        respobj->domain[respobj->num] = bufp;
        if (!LdnsResolver_expandDomainName(rdf, bufp, bufsize)) {
            goto formerr;
        }   // end if
        ++(respobj->num);
    }   // end for

    if (0 == respobj->num) {
        goto nodata;
    }   // end if
    *resp = respobj;
    ldns_rr_list_deep_free(rrlist);
    return DNS_STAT_NOERROR;

  formerr:
    ldns_rr_list_deep_free(rrlist);
    DnsPtrResponse_free(respobj);
    return LdnsResolver_setResolverError(self, DNS_STAT_FORMERR);

  nodata:
    ldns_rr_list_deep_free(rrlist);
    DnsPtrResponse_free(respobj);
    return LdnsResolver_setResolverError(self, DNS_STAT_NOVALIDANSWER);

  noresource:
    ldns_rr_list_deep_free(rrlist);
    DnsPtrResponse_free(respobj);
    return LdnsResolver_setResolverError(self, DNS_STAT_NOMEMORY);
}   // end function: LdnsResolver_lookupPtr

static void
LdnsResolver_free(DnsResolver *base)
{
    if (NULL == base) {
        return;
    }   // end if

    LdnsResolver *self = (LdnsResolver *) base;
    ldns_resolver_deep_free(self->res);
    free(self);
}   // end function: LdnsResolver_free

static const struct DnsResolver_vtbl LdnsResolver_vtbl = {
    "ldns",
    LdnsResolver_free,
    LdnsResolver_getErrorSymbol,
    LdnsResolver_setTimeout,
    LdnsResolver_setRetryCount,
    LdnsResolver_lookupA,
    LdnsResolver_lookupAaaa,
    LdnsResolver_lookupMx,
    LdnsResolver_lookupTxt,
    LdnsResolver_lookupSpf,
    LdnsResolver_lookupPtr,
};

DnsResolver *
LdnsResolver_new(const char *initfile)
{
    LdnsResolver *self = (LdnsResolver *) malloc(sizeof(LdnsResolver));
    if (NULL == self) {
        return NULL;
    }   // end if
    memset(self, 0, sizeof(LdnsResolver));
    ldns_status stat = ldns_resolver_new_frm_file(&(self->res), PTROR(initfile, _PATH_RESCONF));
    if (LDNS_STATUS_OK != stat) {
        goto cleanup;
    }   // end if
    self->vtbl = &LdnsResolver_vtbl;
    return (DnsResolver *) self;

  cleanup:
    LdnsResolver_free((DnsResolver *) self);
    return NULL;
}   // end function: LdnsResolver_new
