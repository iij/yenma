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

#include <sys/socket.h>
#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <resolv.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/nameser.h>
#include <netinet/in.h>

#include "stdaux.h"
#include "dnsresolv.h"
#include "dnsresolv_internal.h"
#include "bindresolver.h"

#if defined(USE_LIBRESOLV) && !defined(NS_MAXMSG)
# define NS_MAXMSG   65535  /* maximum message size */
#endif

typedef struct BindResolver {
    DnsResolver_MEMBER;
    struct __res_state resolver;
    ns_msg msghanlde;
    dns_stat_t status;
    int msglen;
    unsigned char msgbuf[NS_MAXMSG];
} BindResolver;

static dns_stat_t
BindResolver_herrno2statcode(int herrno)
{
    switch (herrno) {
    case NETDB_INTERNAL:
        return DNS_STAT_RESOLVER_INTERNAL;
    case NETDB_SUCCESS:
        return DNS_STAT_NOERROR;
    case HOST_NOT_FOUND:
        return DNS_STAT_NXDOMAIN;
    case TRY_AGAIN:
        return DNS_STAT_SERVFAIL;
    case NO_RECOVERY:  // FORMERR, REFUSED, NOTIMP
        return DNS_STAT_FORMERR;
    case NO_DATA:
        return DNS_STAT_NODATA;
    default:
        return DNS_STAT_RESOLVER_INTERNAL;
    }   // end switch
}   // end function: BindResolver_herrno2statcode

static dns_stat_t
BindResolver_rcode2statcode(int rcode)
{
    switch (rcode) {
    case ns_r_noerror:
        return DNS_STAT_NOERROR;
    case ns_r_formerr:
        return DNS_STAT_FORMERR;
    case ns_r_servfail:
        return DNS_STAT_SERVFAIL;
    case ns_r_nxdomain:
        return DNS_STAT_NXDOMAIN;
    case ns_r_notimpl:
        return DNS_STAT_NOTIMPL;
    case ns_r_refused:
        return DNS_STAT_REFUSED;
    default:
        return DNS_STAT_RESOLVER;
    }   // end switch
}   // end function: BindResolver_rcode2statcode

static dns_stat_t
BindResolver_setHerrno(BindResolver *self, int herrno)
{
    self->status = BindResolver_herrno2statcode(herrno);
    return self->status;    // for caller's convenience
}   // end function: BindResolver_setHerrno

static dns_stat_t
BindResolver_setRcode(BindResolver *self, int rcode)
{
    self->status = BindResolver_rcode2statcode(rcode);
    return self->status;    // for caller's convenience
}   // end function: BindResolver_setRcode

static dns_stat_t
BindResolver_setError(BindResolver *self, dns_stat_t status)
{
    self->status = status;
    return status;  // for caller's convenience
}   // end function: BindResolver_setError

static void
BindResolver_resetErrorState(BindResolver *self)
{
    self->status = DNS_STAT_NOERROR;
}   // end function: BindResolver_resetErrorState

static const char *
BindResolver_getErrorSymbol(const DnsResolver *base)
{
    BindResolver *self = (BindResolver *) base;
    return DnsResolver_symbolizeErrorCode(self->status);
}   // end function: BindResolver_getErrorSymbol

static void
BindResolver_setTimeout(const DnsResolver *base, time_t timeout)
{
    BindResolver *self = (BindResolver *) base;
    self->resolver.retrans = (int) timeout;
}   // end function: BindResolver_setTimeout

static void
BindResolver_setRetryCount(const DnsResolver *base, int retry)
{
    BindResolver *self = (BindResolver *) base;
    self->resolver.retry = retry;
}   // end function: BindResolver_setRetryCount

/*
 * throw a DNS query and receive a response of it
 * @return
 */
static dns_stat_t
BindResolver_query(BindResolver *self, const char *domain, uint16_t rrtype)
{
    BindResolver_resetErrorState(self);
    self->msglen = res_nquery(&self->resolver, domain, ns_c_in, rrtype, self->msgbuf, NS_MAXMSG);
    if (0 > self->msglen) {
        return BindResolver_setHerrno(self, self->resolver.res_h_errno);
    }   // end if
    if (0 > ns_initparse(self->msgbuf, self->msglen, &self->msghanlde)) {
        return BindResolver_setError(self, DNS_STAT_FORMERR);
    }   // end if
    int rcode_flag = ns_msg_getflag(self->msghanlde, ns_f_rcode);
    if (ns_r_noerror != rcode_flag) {
        return BindResolver_setRcode(self, rcode_flag);
    }   // end if
    return DNS_STAT_NOERROR;
}   // end function: BindResolver_query

static dns_stat_t
BindResolver_lookupA(DnsResolver *base, const char *domain, DnsAResponse **resp)
{
    BindResolver *self = (BindResolver *) base;
    int query_stat = BindResolver_query(self, domain, ns_t_a);
    if (DNS_STAT_NOERROR != query_stat) {
        return query_stat;
    }   // end if
    size_t msg_count = ns_msg_count(self->msghanlde, ns_s_an);
    if (0 == msg_count) {
        return BindResolver_setError(self, DNS_STAT_NODATA);
    }   // end if
    DnsAResponse *respobj =
        (DnsAResponse *) malloc(sizeof(DnsAResponse) + msg_count * sizeof(struct in_addr));
    if (NULL == respobj) {
        return BindResolver_setError(self, DNS_STAT_NOMEMORY);
    }   // end if
    memset(respobj, 0, sizeof(DnsAResponse) + msg_count * sizeof(struct in_addr));
    respobj->num = 0;
    for (size_t n = 0; n < msg_count; ++n) {
        ns_rr rr;
        int parse_stat = ns_parserr(&self->msghanlde, ns_s_an, n, &rr);
        if (0 != parse_stat) {
            goto formerr;
        }   // end if
        if (ns_t_a != ns_rr_type(rr)) {
            continue;
        }   // end if
        if (NS_INADDRSZ != ns_rr_rdlen(rr)) {
            goto formerr;
        }   // end if
        memcpy(&(respobj->addr[respobj->num]), ns_rr_rdata(rr), NS_INADDRSZ);
        ++(respobj->num);
    }   // end for
    if (0 == respobj->num) {
        goto nodata;
    }   // end if
    *resp = respobj;
    return DNS_STAT_NOERROR;

  formerr:
    DnsAResponse_free(respobj);
    return BindResolver_setError(self, DNS_STAT_FORMERR);

  nodata:
    DnsAResponse_free(respobj);
    return BindResolver_setError(self, DNS_STAT_NOVALIDANSWER);
}   // end function: BindResolver_lookupA

static dns_stat_t
BindResolver_lookupAaaa(DnsResolver *base, const char *domain, DnsAaaaResponse **resp)
{
    BindResolver *self = (BindResolver *) base;
    int query_stat = BindResolver_query(self, domain, ns_t_aaaa);
    if (DNS_STAT_NOERROR != query_stat) {
        return query_stat;
    }   // end if
    size_t msg_count = ns_msg_count(self->msghanlde, ns_s_an);
    if (0 == msg_count) {
        return BindResolver_setError(self, DNS_STAT_NODATA);
    }   // end if
    DnsAaaaResponse *respobj =
        (DnsAaaaResponse *) malloc(sizeof(DnsAaaaResponse) + msg_count * sizeof(struct in6_addr));
    if (NULL == respobj) {
        return BindResolver_setError(self, DNS_STAT_NOMEMORY);
    }   // end if
    memset(respobj, 0, sizeof(DnsAaaaResponse) + msg_count * sizeof(struct in6_addr));
    respobj->num = 0;
    for (size_t n = 0; n < msg_count; ++n) {
        ns_rr rr;
        int parse_stat = ns_parserr(&self->msghanlde, ns_s_an, n, &rr);
        if (0 != parse_stat) {
            goto formerr;
        }   // end if
        if (ns_t_aaaa != ns_rr_type(rr)) {
            continue;
        }   // end if
        if (NS_IN6ADDRSZ != ns_rr_rdlen(rr)) {
            goto formerr;
        }   // end if
        memcpy(&(respobj->addr[respobj->num]), ns_rr_rdata(rr), NS_IN6ADDRSZ);
        ++(respobj->num);
    }   // end for
    if (0 == respobj->num) {
        goto nodata;
    }   // end if
    *resp = respobj;
    return DNS_STAT_NOERROR;

  formerr:
    DnsAaaaResponse_free(respobj);
    return BindResolver_setError(self, DNS_STAT_FORMERR);

  nodata:
    DnsAaaaResponse_free(respobj);
    return BindResolver_setError(self, DNS_STAT_NOVALIDANSWER);
}   // end function: BindResolver_lookupAaaa

static dns_stat_t
BindResolver_lookupMx(DnsResolver *base, const char *domain, DnsMxResponse **resp)
{
    BindResolver *self = (BindResolver *) base;
    int query_stat = BindResolver_query(self, domain, ns_t_mx);
    if (DNS_STAT_NOERROR != query_stat) {
        return query_stat;
    }   // end if
    size_t msg_count = ns_msg_count(self->msghanlde, ns_s_an);
    if (0 == msg_count) {
        return BindResolver_setError(self, DNS_STAT_NODATA);
    }   // end if
    DnsMxResponse *respobj =
        (DnsMxResponse *) malloc(sizeof(DnsMxResponse) + msg_count * sizeof(struct mxentry *));
    if (NULL == respobj) {
        return BindResolver_setError(self, DNS_STAT_NOMEMORY);
    }   // end if
    memset(respobj, 0, sizeof(DnsMxResponse) + msg_count * sizeof(struct mxentry *));
    respobj->num = 0;
    for (size_t n = 0; n < msg_count; ++n) {
        ns_rr rr;
        int parse_stat = ns_parserr(&self->msghanlde, ns_s_an, n, &rr);
        if (0 != parse_stat) {
            goto formerr;
        }   // end if
        if (ns_t_mx != ns_rr_type(rr)) {
            continue;
        }   // end if
        const unsigned char *rdata = ns_rr_rdata(rr);
        if (ns_rr_rdlen(rr) < NS_INT16SZ) {
            goto formerr;
        }   // end if

        int preference = ns_get16(rdata);
        rdata += NS_INT16SZ;

        // NOTE: Not sure that NS_MAXDNAME is enough size of buffer for ns_name_uncompress().
        // "dig" supplied with bind8 uses NS_MAXDNAME for this.
        char dnamebuf[NS_MAXDNAME];
        int dnamelen =
            ns_name_uncompress(self->msgbuf, self->msgbuf + self->msglen, rdata, dnamebuf,
                               sizeof(dnamebuf));
        if (NS_INT16SZ + dnamelen != ns_rr_rdlen(rr)) {
            goto formerr;
        }   // end if
        size_t domainlen = strlen(dnamebuf);    // ns_name_uncompress() terminates dnamebuf with NULL character
        respobj->exchange[respobj->num] =
            (struct mxentry *) malloc(sizeof(struct mxentry) + sizeof(char[domainlen + 1]));
        if (NULL == respobj->exchange[respobj->num]) {
            goto noresource;
        }   // end if
        respobj->exchange[respobj->num]->preference = preference;
        memcpy(respobj->exchange[respobj->num]->domain, dnamebuf, domainlen + 1);
        ++(respobj->num);
    }   // end for
    if (0 == respobj->num) {
        goto nodata;
    }   // end if
    *resp = respobj;
    return DNS_STAT_NOERROR;

  formerr:
    DnsMxResponse_free(respobj);
    return BindResolver_setError(self, DNS_STAT_FORMERR);

  nodata:
    DnsMxResponse_free(respobj);
    return BindResolver_setError(self, DNS_STAT_NOVALIDANSWER);

  noresource:
    DnsMxResponse_free(respobj);
    return BindResolver_setError(self, DNS_STAT_NOMEMORY);
}   // end function: BindResolver_lookupMx

/**
 * @return DNS_STAT_NOERROR on success.
 */
static int
BindResolver_lookupTxtData(BindResolver *self, uint16_t rrtype, const char *domain,
                           DnsTxtResponse **resp)
{
    int query_stat = BindResolver_query(self, domain, rrtype);
    if (DNS_STAT_NOERROR != query_stat) {
        return query_stat;
    }   // end if
    size_t msg_count = ns_msg_count(self->msghanlde, ns_s_an);
    if (0 == msg_count) {
        return BindResolver_setError(self, DNS_STAT_NODATA);
    }   // end if
    DnsTxtResponse *respobj =
        (DnsTxtResponse *) malloc(sizeof(DnsTxtResponse) + msg_count * sizeof(char *));
    if (NULL == respobj) {
        return BindResolver_setError(self, DNS_STAT_NOMEMORY);
    }   // end if
    memset(respobj, 0, sizeof(DnsTxtResponse) + msg_count * sizeof(char *));
    respobj->num = 0;
    for (size_t n = 0; n < msg_count; ++n) {
        ns_rr rr;
        int parse_stat = ns_parserr(&self->msghanlde, ns_s_an, n, &rr);
        if (0 != parse_stat) {
            goto formerr;
        }   // end if
        if (rrtype != ns_rr_type(rr)) {
            continue;
        }   // end if
        // the size of the TXT data should be smaller than RDLEN
        respobj->data[respobj->num] = (char *) malloc(ns_rr_rdlen(rr));
        if (NULL == respobj->data[respobj->num]) {
            goto noresource;
        }   // end if
        const unsigned char *rdata = ns_rr_rdata(rr);
        const unsigned char *rdata_tail = ns_rr_rdata(rr) + ns_rr_rdlen(rr);
        char *bufp = respobj->data[respobj->num];
        while (rdata < rdata_tail) {
            // check if the length octet is less than RDLEN
            if (rdata_tail < rdata + (*rdata) + 1) {
                free(respobj->data[respobj->num]);
                goto formerr;
            }   // end if
            memcpy(bufp, rdata + 1, *rdata);
            bufp += (size_t) *rdata;
            rdata += (size_t) *rdata + 1;
        }   // end while
        *bufp = '\0';   // terminate with NULL
        ++(respobj->num);
    }   // end for
    if (0 == respobj->num) {
        goto nodata;
    }   // end if
    *resp = respobj;
    return DNS_STAT_NOERROR;

  formerr:
    DnsTxtResponse_free(respobj);
    return BindResolver_setError(self, DNS_STAT_FORMERR);

  nodata:
    DnsTxtResponse_free(respobj);
    return BindResolver_setError(self, DNS_STAT_NOVALIDANSWER);

  noresource:
    DnsTxtResponse_free(respobj);
    return BindResolver_setError(self, DNS_STAT_NOMEMORY);
}   // end function: BindResolver_lookupTxtData

static dns_stat_t
BindResolver_lookupTxt(DnsResolver *base, const char *domain, DnsTxtResponse **resp)
{
    BindResolver *self = (BindResolver *) base;
    return BindResolver_lookupTxtData(self, ns_t_txt, domain, resp);
}   // end function: BindResolver_lookupTxt

static dns_stat_t
BindResolver_lookupSpf(DnsResolver *base, const char *domain, DnsSpfResponse **resp)
{
    BindResolver *self = (BindResolver *) base;
    return BindResolver_lookupTxtData(self, 99 /* as ns_t_spf */ , domain, resp);
}   // end function: BindResolver_lookupSpf

static dns_stat_t
BindResolver_lookupPtr(DnsResolver *base, sa_family_t sa_family, const void *addr,
                       DnsPtrResponse **resp)
{
    BindResolver *self = (BindResolver *) base;
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
        return BindResolver_setError(self, DNS_STAT_BADREQUEST);
    }   // end if

    int query_stat = BindResolver_query(self, domain, ns_t_ptr);
    if (DNS_STAT_NOERROR != query_stat) {
        return query_stat;
    }   // end if
    size_t msg_count = ns_msg_count(self->msghanlde, ns_s_an);
    if (0 == msg_count) {
        return BindResolver_setError(self, DNS_STAT_NODATA);
    }   // end if
    DnsPtrResponse *respobj =
        (DnsPtrResponse *) malloc(sizeof(DnsPtrResponse) + msg_count * sizeof(char *));
    if (NULL == respobj) {
        return BindResolver_setError(self, DNS_STAT_NOMEMORY);
    }   // end if
    memset(respobj, 0, sizeof(DnsPtrResponse) + msg_count * sizeof(char *));
    respobj->num = 0;
    for (size_t n = 0; n < msg_count; ++n) {
        ns_rr rr;
        int parse_stat = ns_parserr(&self->msghanlde, ns_s_an, n, &rr);
        if (0 != parse_stat) {
            goto formerr;
        }   // end if
        if (ns_t_ptr != ns_rr_type(rr)) {
            continue;
        }   // end if
        // NOTE: Not sure that NS_MAXDNAME is enough size of buffer for ns_name_uncompress().
        // "dig" supplied with bind8 uses NS_MAXDNAME for this.
        char dnamebuf[NS_MAXDNAME];
        int dnamelen =
            ns_name_uncompress(self->msgbuf, self->msgbuf + self->msglen, ns_rr_rdata(rr), dnamebuf,
                               sizeof(dnamebuf));
        if (dnamelen != ns_rr_rdlen(rr)) {
            goto formerr;
        }   // end if
        respobj->domain[respobj->num] = strdup(dnamebuf);   // ns_name_uncompress() terminates dnamebuf with NULL character
        if (NULL == respobj->domain[respobj->num]) {
            goto noresource;
        }   // end if
        ++(respobj->num);
    }   // end for
    if (0 == respobj->num) {
        goto nodata;
    }   // end if
    *resp = respobj;
    return DNS_STAT_NOERROR;

  formerr:
    DnsPtrResponse_free(respobj);
    return BindResolver_setError(self, DNS_STAT_FORMERR);

  nodata:
    DnsPtrResponse_free(respobj);
    return BindResolver_setError(self, DNS_STAT_NOVALIDANSWER);

  noresource:
    DnsPtrResponse_free(respobj);
    return BindResolver_setError(self, DNS_STAT_NOMEMORY);
}   // end function: BindResolver_lookupPtr

static void
BindResolver_free(DnsResolver *base)
{
    if (NULL == base) {
        return;
    }   // end if

    BindResolver *self = (BindResolver *) base;
#if !defined(USE_LIBRESOLV)
    res_ndestroy(&self->resolver);
#else
    // res_nclose() in glibc 2.3.x or earlier will cause memory leak under the multithreaded environment
    // (and is not supposed to be called directly).
    // this section is *not* tested and activate at your own risk.
    res_nclose(&self->resolver);
#endif
    free(self);
}   // end function: BindResolver_free

static const struct DnsResolver_vtbl BindResolver_vtbl = {
    "bind",
    BindResolver_free,
    BindResolver_getErrorSymbol,
    BindResolver_setTimeout,
    BindResolver_setRetryCount,
    BindResolver_lookupA,
    BindResolver_lookupAaaa,
    BindResolver_lookupMx,
    BindResolver_lookupTxt,
    BindResolver_lookupSpf,
    BindResolver_lookupPtr,
};

DnsResolver *
BindResolver_new(const char *initfile __attribute__((unused)))
{
    BindResolver *self = (BindResolver *) malloc(sizeof(BindResolver));
    if (NULL == self) {
        return NULL;
    }   // end if
    memset(self, 0, sizeof(BindResolver));
    if (NETDB_SUCCESS != res_ninit(&self->resolver)) {
        goto cleanup;
    }   // end if
    self->vtbl = &BindResolver_vtbl;
    return (DnsResolver *) self;

  cleanup:
    BindResolver_free((DnsResolver *) self);
    return NULL;
}   // end function: BindResolver_new
