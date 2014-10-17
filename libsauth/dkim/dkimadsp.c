/*
 * Copyright (c) 2006-2014 Internet Initiative Japan Inc. All rights reserved.
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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "stdaux.h"
#include "ptrop.h"
#include "loghandler.h"
#include "dkimlogger.h"
#include "inetdomain.h"
#include "dnsresolv.h"
#include "dkim.h"
#include "dkimspec.h"
#include "dkimenum.h"
#include "dkimtaglistobject.h"
#include "dkimconverter.h"
#include "dkimadsp.h"

struct DkimAdsp {
    DkimTagListObject_MEMBER;
    DkimAdspPractice practice;  // adsp-dkim-tag
};

static DkimStatus DkimAdsp_parse_dkim(DkimTagListObject *base, const DkimTagParseContext *context,
                                      const char **nextp);

static const DkimTagListObjectFieldMap dkim_adsp_field_table[] = {
    {"dkim", DkimAdsp_parse_dkim, true, NULL},
    {NULL, NULL, false, NULL},  // sentinel
};

/*
 * [RFC5617] 4.2.1.
 * adsp-dkim-tag = %x64.6b.69.6d *WSP "=" *WSP
 *                 ("unknown" / "all" / "discardable" /
 *                  x-adsp-dkim-tag)
 * x-adsp-dkim-tag = hyphenated-word   ; for future extension
 * ; hyphenated-word is defined in RFC 4871
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION tag-value syntax violation
 */
DkimStatus
DkimAdsp_parse_dkim(DkimTagListObject *base, const DkimTagParseContext *context, const char **nextp)
{
    DkimAdsp *self = (DkimAdsp *) base;

    /*
     * a "valid ADSP record" must starts with a valid "dkim" tag
     * [RFC5617] 4.2.1.
     * Every ADSP record
     * MUST start with an outbound signing-practices tag, so the first four
     * characters of the record are lowercase "dkim", followed by optional
     * whitespace and "=".
     */
    if (0 != context->tag_no) {
        *nextp = context->value_head;
        DkimLogPermFail("adsp-dkim-tag appeared not at the front of ADSP record: near %.50s",
                        context->value_head);
        return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
    }   // end if

    self->practice = DkimEnum_lookupPracticeByNameSlice(context->value_head, context->value_tail);
    if (DKIM_ADSP_PRACTICE_NULL == self->practice) {
        /*
         * [RFC5617] 4.2.1.
         * Any other values are treated as "unknown".
         */
        LogInfo("unsupported outbound signing practice (treated as \"unknown\"): dkim=%.*s",
                (int) (context->value_tail - context->value_head), context->value_head);
        self->practice = DKIM_ADSP_PRACTICE_UNKNOWN;
    }   // end if
    *nextp = context->value_tail;
    return DSTAT_OK;
}   // end function: DkimAdsp_parse_dkim

////////////////////////////////////////////////////////////////////////

/**
 * @param policy
 * @param keyval
 * @param dstat
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION tag-value syntax violation
 * @error DSTAT_PERMFAIL_MISSING_REQUIRED_TAG missing required tag
 * @error DSTAT_PERMFAIL_TAG_DUPLICATED multiple identical tags are found
 * @error DSTAT_SYSERR_IMPLERROR obvious implementation error
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 */
DkimStatus
DkimAdsp_build(const char *keyval, DkimAdsp **adsp_record)
{
    assert(NULL != keyval);
    assert(NULL != adsp_record);

    DkimAdsp *self = (DkimAdsp *) malloc(sizeof(DkimAdsp));
    if (NULL == self) {
        LogNoResource();
        return DSTAT_SYSERR_NORESOURCE;
    }   // end if
    memset(self, 0, sizeof(DkimAdsp));
    self->ftbl = dkim_adsp_field_table;

    /*
     * [RFC5617] 4.1.
     * Note:   ADSP changes the "Tag=Value List" syntax from [RFC4871] to
     *         use WSP rather than FWS in its DNS records.
     */
    DkimStatus build_stat =
        DkimTagListObject_build((DkimTagListObject *) self, keyval, STRTAIL(keyval), true, false);
    if (DSTAT_OK != build_stat) {
        DkimAdsp_free(self);
        return build_stat;
    }   // end if

    *adsp_record = self;
    return DSTAT_OK;
}   // end function: DkimAdsp_build

/**
 * release DkimAdsp object
 * @param self DkimAdsp object to release
 */
void
DkimAdsp_free(DkimAdsp *self)
{
    free(self);
}   // end function: DkimAdsp_free

/**
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_INFO_ADSP_NOT_EXIST ADSP record have not found
 * @error DSTAT_PERMFAIL_MULTIPLE_ADSP_RECORD multiple ADSP records are found
 * @error DSTAT_TMPERR_DNS_ERROR_RESPONSE DNS lookup error (received error response)
 * @error DSTAT_SYSERR_DNS_LOOKUP_FAILURE DNS lookup error (failed to lookup itself)
 * @error DSTAT_SYSERR_IMPLERROR obvious implementation error
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 */
static DkimStatus
DkimAdsp_query(DnsResolver *resolver, const char *domain, DkimAdsp **adsp_record)
{
    assert(NULL != resolver);
    assert(NULL != domain);

    // lookup ADSP record
    DnsTxtResponse *txt_rr = NULL;
    dns_stat_t txtquery_stat = DnsResolver_lookupTxt(resolver, domain, &txt_rr);
    switch (txtquery_stat) {
    case DNS_STAT_NOERROR:;
        // one or more TXT RRs are found

        /*
         * [RFC5617] 4.3.
         * If the result of this query is a NOERROR response (rcode=0 in
         * [RFC1035]) with an answer that is a single record that is a valid
         * ADSP record, use that record, and the algorithm terminates.
         */
        if (0 == txt_rr->num) {
            /*
             * no TXT records are found
             * [RFC5617] 4.3.
             * If the result of the query is NXDOMAIN or NOERROR with zero
             * records, there is no ADSP record.
             */
            DnsTxtResponse_free(txt_rr);
            return DSTAT_INFO_DNSRR_NOT_EXIST;
        } else if (1 < txt_rr->num) {
            /*
             * multiple TXT records are found
             * [RFC5617] 4.3.
             * If the result of the query
             * contains more than one record, or a record that is not a valid
             * ADSP record, the ADSP result is undefined.
             */
            DnsTxtResponse_free(txt_rr);
            return DSTAT_PERMFAIL_MULTIPLE_DNSRR;
        }   // end if

        // only one TXT record is found, and now, try to parse as ADSP record
        const char *txtrecord = txt_rr->data[0];
        DkimAdsp *self = NULL;
        DkimStatus build_stat = DkimAdsp_build(txtrecord, &self);
        if (DSTAT_OK == build_stat) {
            // parsed as a valid ADSP record
            *adsp_record = self;
            DnsTxtResponse_free(txt_rr);
            return DSTAT_OK;
        } else if (DSTAT_ISCRITERR(build_stat)) {
            // propagate system errors as-is
            DkimLogSysError
                ("System error has occurred while parsing ADSP record: domain=%s, error=%s, record=%s",
                 domain, DkimStatus_getSymbol(build_stat), NNSTR(txtrecord));
            DnsTxtResponse_free(txt_rr);
            return build_stat;
        } else if (DSTAT_ISPERMFAIL(build_stat)) {
            /*
             * treat syntax errors on ADSP record as DNS NODATA response
             *
             * [RFC5617] 4.1.
             * Records not in compliance with that syntax
             * or the syntax of individual tags described in Section 4.3 MUST be
             * ignored (considered equivalent to a NODATA result) for purposes of
             * ADSP, although they MAY cause the logging of warning messages via an
             * appropriate system logging mechanism.
             */
            LogDebug("ADSP record candidate discarded: domain=%s, error=%s, record=%s",
                     domain, DkimStatus_getSymbol(build_stat), NNSTR(txtrecord));
        } else {
            LogNotice("DkimAdsp_build failed: domain=%s, error=%s, record=%s",
                      domain, DkimStatus_getSymbol(build_stat), NNSTR(txtrecord));
        }   // end if

        // the TXT RR is not a valid ADSP record
        DnsTxtResponse_free(txt_rr);
        txt_rr = NULL;
        // fallthrough

    case DNS_STAT_NXDOMAIN:
    case DNS_STAT_NODATA:
    case DNS_STAT_NOVALIDANSWER:
        /*
         * no TXT (and ADSP) records are found
         *
         * [RFC5617] 4.3.
         * If the result of the query is NXDOMAIN or NOERROR with zero
         * records, there is no ADSP record.  If the result of the query
         * contains more than one record, or a record that is not a valid
         * ADSP record, the ADSP result is undefined.
         */
        LogDebug("No ADSP record is found on DNS: qname=%s", domain);
        return DSTAT_INFO_DNSRR_NOT_EXIST;

    case DNS_STAT_FORMERR:
    case DNS_STAT_SERVFAIL:
    case DNS_STAT_NOTIMPL:
    case DNS_STAT_REFUSED:
    case DNS_STAT_YXDOMAIN:
    case DNS_STAT_YXRRSET:
    case DNS_STAT_NXRRSET:
    case DNS_STAT_NOTAUTH:
    case DNS_STAT_NOTZONE:
    case DNS_STAT_RESERVED11:
    case DNS_STAT_RESERVED12:
    case DNS_STAT_RESERVED13:
    case DNS_STAT_RESERVED14:
    case DNS_STAT_RESERVED15:
    case DNS_STAT_RESOLVER:
    case DNS_STAT_RESOLVER_INTERNAL:
        /*
         * [RFC5617] 4.3.
         * If a query results in a "SERVFAIL" error response (rcode=2 in
         * [RFC1035]), the algorithm terminates without returning a result;
         * possible actions include queuing the message or returning an SMTP
         * error indicating a temporary failure.
         */
        LogDnsError("txt", domain, "DKIM ADSP record", DnsResolver_getErrorSymbol(resolver));
        return DSTAT_TMPERR_DNS_ERROR_RESPONSE;

    case DNS_STAT_SYSTEM:
        DkimLogSysError("System error occurred on DNS lookup: rrtype=txt, qname=%s, error=%s",
                        domain, DnsResolver_getErrorSymbol(resolver));
        return DSTAT_SYSERR_DNS_LOOKUP_FAILURE;

    case DNS_STAT_NOMEMORY:
        LogNoResource();
        return DSTAT_SYSERR_NORESOURCE;

    case DNS_STAT_BADREQUEST:
    default:
        DkimLogImplError
            ("DnsResolver_lookupTxt returns unexpected value: value=0x%x, rrtype=txt, qname=%s",
             txtquery_stat, domain);
        return DSTAT_SYSERR_IMPLERROR;
    }   // end switch
}   // end function: DkimAdsp_query

/**
 * Check whether a given Author Domain is within scope for ADSP.
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_INFO_ADSP_NXDOMAIN Author Domain does not exist (NXDOMAIN)
 * @error DSTAT_TMPERR_DNS_ERROR_RESPONSE DNS lookup error (received error response)
 * @error DSTAT_SYSERR_DNS_LOOKUP_FAILURE DNS lookup error (failed to lookup itself)
 * @error DSTAT_SYSERR_IMPLERROR obvious implementation error
 */
static DkimStatus
DkimAdsp_checkDomainScope(DnsResolver *resolver, const char *domain)
{
    assert(NULL != resolver);
    assert(NULL != domain);

    /*
     * [RFC5617] 4.3.
     * The host MUST perform a DNS query for a record corresponding to
     * the Author Domain (with no prefix).  The type of the query can be
     * of any type, since this step is only to determine if the domain
     * itself exists in DNS.  This query MAY be done in parallel with the
     * query to fetch the named ADSP Record.  If the result of this query
     * is that the Author Domain does not exist in the DNS (often called
     * an NXDOMAIN error, rcode=3 in [RFC1035]), the algorithm MUST
     * terminate with an error indicating that the domain is out of
     * scope.  Note that a result with rcode=0 but no records (often
     * called NODATA) is not the same as NXDOMAIN.
     *
     *    NON-NORMATIVE DISCUSSION: Any resource record type could be
     *    used for this query since the existence of a resource record of
     *    any type will prevent an NXDOMAIN error.  MX is a reasonable
     *    choice for this purpose because this record type is thought to
     *    be the most common for domains used in email, and will
     *    therefore produce a result that can be more readily cached than
     *    a negative result.
     */

    DnsMxResponse *mx_rr = NULL;
    dns_stat_t mxquery_stat = DnsResolver_lookupMx(resolver, domain, &mx_rr);
    switch (mxquery_stat) {
    case DNS_STAT_NOERROR:
        DnsMxResponse_free(mx_rr);
        // fall through

    case DNS_STAT_NODATA:
    case DNS_STAT_NOVALIDANSWER:
        return DSTAT_OK;

    case DNS_STAT_NXDOMAIN:
        DkimLogPermFail("The author domain does not exist: rrtype=mx, domain=%s, error=%s",
                        domain, DnsResolver_getErrorSymbol(resolver));
        return DSTAT_INFO_DNSRR_NXDOMAIN;

    case DNS_STAT_FORMERR:
    case DNS_STAT_SERVFAIL:
    case DNS_STAT_NOTIMPL:
    case DNS_STAT_REFUSED:
    case DNS_STAT_YXDOMAIN:
    case DNS_STAT_YXRRSET:
    case DNS_STAT_NXRRSET:
    case DNS_STAT_NOTAUTH:
    case DNS_STAT_NOTZONE:
    case DNS_STAT_RESERVED11:
    case DNS_STAT_RESERVED12:
    case DNS_STAT_RESERVED13:
    case DNS_STAT_RESERVED14:
    case DNS_STAT_RESERVED15:
    case DNS_STAT_RESOLVER:
    case DNS_STAT_RESOLVER_INTERNAL:
        LogDnsError("mx", domain, "DKIM ADSP Author domain check",
                    DnsResolver_getErrorSymbol(resolver));
        return DSTAT_TMPERR_DNS_ERROR_RESPONSE;

    case DNS_STAT_SYSTEM:
        DkimLogSysError("System error occurred on DNS lookup: rrtype=mx, qname=%s, error=%s",
                        domain, DnsResolver_getErrorSymbol(resolver));
        return DSTAT_SYSERR_DNS_LOOKUP_FAILURE;

    case DNS_STAT_NOMEMORY:
        LogNoResource();
        return DSTAT_SYSERR_NORESOURCE;

    case DNS_STAT_BADREQUEST:
    default:
        DkimLogImplError
            ("DnsResolver_lookupMx returns unexpected value: value=0x%x, rrtype=mx, qname=%s",
             mxquery_stat, domain);
        return DSTAT_SYSERR_IMPLERROR;
    }   // end switch
}   // end function: DkimAdsp_checkDomainScope

static DkimStatus
DkimAdsp_fetch(DnsResolver *resolver, const char *authordomain, DkimAdsp **adsp_record)
{
    // build domain name to look-up an ADSP record
    size_t dkimdomainlen =
        strlen(authordomain) + sizeof(DKIM_DNS_ADSP_SELECTOR "." DKIM_DNS_NAMESPACE ".");
    char dkimdomain[dkimdomainlen];

    int ret =
        snprintf(dkimdomain, dkimdomainlen, DKIM_DNS_ADSP_SELECTOR "." DKIM_DNS_NAMESPACE ".%s",
                 authordomain);
    if ((int) dkimdomainlen <= ret) {
        DkimLogImplError("buffer too small: bufsize=%zu, writelen=%d, domain=%s",
                         dkimdomainlen, ret, authordomain);
        return DSTAT_SYSERR_IMPLERROR;
    }   // end if

    return DkimAdsp_query(resolver, dkimdomain, adsp_record);
}   // end function: DkimAdsp_fetch

/**
 * @error DSTAT_INFO_ADSP_NXDOMAIN Author Domain does not exist (NXDOMAIN)
 * @error DSTAT_INFO_ADSP_NOT_EXIST ADSP record have not found
 * @error DSTAT_PERMFAIL_MULTIPLE_ADSP_RECORD multiple ADSP records are found
 * @error DSTAT_TMPERR_DNS_ERROR_RESPONSE DNS lookup error (received error response)
 * @error DSTAT_SYSERR_DNS_LOOKUP_FAILURE DNS lookup error (failed to lookup itself)
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 * @error DSTAT_SYSERR_IMPLERROR obvious implementation error
 */
DkimStatus
DkimAdsp_lookup(const char *authordomain, DnsResolver *resolver, DkimAdsp **adsp_record)
{
    assert(NULL != authordomain);
    assert(NULL != resolver);

    // Check Domain Scope:
    DkimStatus check_stat = DkimAdsp_checkDomainScope(resolver, authordomain);
    if (DSTAT_OK != check_stat) {
        return check_stat;
    }   // end if

    // Fetch Named ADSP Record:
    return DkimAdsp_fetch(resolver, authordomain, adsp_record);
}   // end function: DkimAdsp_lookup

////////////////////////////////////////////////////////////////////////
// accessor

DkimAdspPractice
DkimAdsp_getPractice(const DkimAdsp *self)
{
    return self->practice;
}   // end function: DkimAdsp_getPractice
