/*
 * Copyright (c) 2012-2014 Internet Initiative Japan Inc. All rights reserved.
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
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/err.h>
#include <openssl/evp.h>

#include "stdaux.h"
#include "ptrop.h"
#include "pstring.h"
#include "xskip.h"
#include "loghandler.h"
#include "dkimlogger.h"
#include "inetdomain.h"
#include "dnsresolv.h"
#include "openssl_compat.h"
#include "dkim.h"
#include "dkimspec.h"
#include "dkimenum.h"
#include "dkimtaglistobject.h"
#include "dkimconverter.h"
#include "dkimatps.h"

struct DkimAtps {
    DkimTagListObject_MEMBER;
    char *domain;               // atps-d-tag
};

static DkimStatus DkimAtps_parse_v(DkimTagListObject *base, const DkimTagParseContext *context,
                                   const char **nextp);
static DkimStatus DkimAtps_parse_d(DkimTagListObject *base, const DkimTagParseContext *context,
                                   const char **nextp);

static const DkimTagListObjectFieldMap dkim_atps_field_table[] = {
    {"v", DkimAtps_parse_v, true, NULL},
    {"d", DkimAtps_parse_d, false, NULL},
    {NULL, NULL, false, NULL},  // sentinel
};

/*
 * @param buflen must include a space for null characters like strlcpy.
 */
static char *
_strlowercpy(char *dst, const char *src, size_t buflen)
{
    const char *s;
    char *d;
    for (s = src, d = dst; 1 < buflen && '\0' != *s; ++s, ++d, --buflen) {
        *d = tolower(*s);
    }   // end for
    if (0 < buflen) {
        *d = '\0';
    }   // end if
    return dst;
}   // end function: _strlowercpy

/*
 * [RFC6541] 4.4.
 * atps-v-tag = %x76 [FWS] "=" [FWS] %x41.54.50.53.31
 */
DkimStatus
DkimAtps_parse_v(DkimTagListObject *base __attribute__((unused)),
                 const DkimTagParseContext *context, const char **nextp)
{
    /*
     * appearance at the head of record (0 == context->tag_no)
     * or set as default value (DKIM_TAGLISTOBJECT_TAG_NO_DEFAULT_VALUE == context->tag_no) are accepted.
     * error otherwise.
     */
    if (DKIM_TAGLISTOBJECT_TAG_NO_AS_DEFAULT_VALUE != context->tag_no && 0 < context->tag_no) {
        *nextp = context->value_head;
        DkimLogPermFail("atps-v-tag appeared not at the front of ATPS record: near %.50s",
                        context->value_head);
        return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
    }   // end if

    // compare "ATPS1" tag case-sensitively
    if (0 < XSkip_string(context->value_head, context->value_tail, ATPS1_VERSION_TAG, nextp)) {
        return DSTAT_OK;
    } else {
        *nextp = context->value_head;
        DkimLogPermFail("unsupported ATPS record version tag: near %.50s", context->value_head);
        return DSTAT_PERMFAIL_INCOMPATIBLE_KEY_VERSION;
    }   // end if
}   // end function: DkimAtps_parse_v

/*
 * [RFC6541] 4.4.
 * atps-d-tag = %x64 [FWS] "=" [FWS] domain-name
 */
DkimStatus
DkimAtps_parse_d(DkimTagListObject *base, const DkimTagParseContext *context, const char **nextp)
{
    DkimAtps *self = (DkimAtps *) base;

    // Does value match domain-name?
    if (0 >= XSkip_domainName(context->value_head, context->value_tail, nextp)) {
        DkimLogPermFail("atps-d-tag doesn't match domain-name: near %.50s", context->value_head);
        return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
    }   // end if

    self->domain = strpdup(context->value_head, *nextp);
    if (NULL == self->domain) {
        LogNoResource();
        return DSTAT_SYSERR_NORESOURCE;
    }   // end if

    return DSTAT_OK;
}   // end function: DkimAtps_parse_d

////////////////////////////////////////////////////////////////////////

/**
 * @param policy
 * @param keyval
 * @param record
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION tag-value syntax violation
 * @error DSTAT_PERMFAIL_MISSING_REQUIRED_TAG missing required tag
 * @error DSTAT_PERMFAIL_TAG_DUPLICATED multiple identical tags are found
 * @error DSTAT_SYSERR_IMPLERROR obvious implementation error
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 */
DkimStatus
DkimAtps_build(const char *keyval, DkimAtps **atps_record)
{
    assert(NULL != keyval);
    assert(NULL != atps_record);

    DkimAtps *self = (DkimAtps *) malloc(sizeof(DkimAtps));
    if (NULL == self) {
        LogNoResource();
        return DSTAT_SYSERR_NORESOURCE;
    }   // end if
    memset(self, 0, sizeof(DkimAtps));
    self->ftbl = dkim_atps_field_table;

    /*
     * [RFC6541] 4.4.
     * A valid ATPS reply consists of a sequence of tag=value pairs as
     * described in Section 3.2 of [DKIM].
     */
    DkimStatus build_stat =
        DkimTagListObject_build((DkimTagListObject *) self, keyval, STRTAIL(keyval), false, false);
    if (DSTAT_OK != build_stat) {
        DkimAtps_free(self);
        return build_stat;
    }   // end if

    *atps_record = self;
    return DSTAT_OK;
}   // end function: DkimAtps_build

/**
 * release DkimAtps object
 * @param self DkimAtps object to release
 */
void
DkimAtps_free(DkimAtps *self)
{
    if (NULL == self) {
        return;
    }   // end if

    free(self->domain);
    free(self);
}   // end function: DkimAtps_free

/**
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_INFO_DNSRR_NOT_EXIST ATPS record have not found
 * @error DSTAT_TMPERR_DNS_ERROR_RESPONSE DNS lookup error (received error response)
 * @error DSTAT_SYSERR_DNS_LOOKUP_FAILURE DNS lookup error (failed to lookup itself)
 * @error DSTAT_SYSERR_IMPLERROR obvious implementation error
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 */
static DkimStatus
DkimAtps_query(DnsResolver *resolver, const char *qname, const char *sdid, DkimAtps **atps_record)
{
    assert(NULL != resolver);
    assert(NULL != qname);

    // lookup ATPS record
    DnsTxtResponse *txt_rr = NULL;
    dns_stat_t txtquery_stat = DnsResolver_lookupTxt(resolver, qname, &txt_rr);
    switch (txtquery_stat) {
    case DNS_STAT_NOERROR:;
        /*
         * [RFC6541] 4.4.
         * o  An answer is returned (i.e., [DNS] reply code NOERROR with at
         *    least one answer) containing a valid ATPS reply.  In this case,
         *    the protocol has been satisfied and the Verifier can conclude that
         *    the signing domain is authorized by the ADMD to sign its mail.
         *    Further queries SHOULD NOT be initiated.
         */
        if (0 == txt_rr->num) {
            // no TXT records are found
            DnsTxtResponse_free(txt_rr);
            return DSTAT_INFO_DNSRR_NOT_EXIST;
        }   // end if

        for (size_t txtrr_idx = 0; txtrr_idx < txt_rr->num; ++txtrr_idx) {
            const char *txtrecord = txt_rr->data[txtrr_idx];
            DkimAtps *self = NULL;
            DkimStatus build_stat = DkimAtps_build(txtrecord, &self);
            if (DSTAT_OK == build_stat) {
                // parsed as a valid ATPS record
                // check if atps-d-tag matches sdid
                if (NULL != self->domain && !InetDomain_equals(self->domain, sdid)) {
                    LogDebug
                        ("ATPS record candidate discarded due to domain mismatch: domain=%s, sdid=%s, error=%s, record=%s",
                         qname, sdid, DkimStatus_getSymbol(build_stat), NNSTR(txtrecord));
                    continue;
                }   // end if
                *atps_record = self;
                DnsTxtResponse_free(txt_rr);
                return DSTAT_OK;
            } else if (DSTAT_ISCRITERR(build_stat)) {
                // propagate system errors as-is
                DkimLogSysError
                    ("System error has occurred while parsing ATPS record: domain=%s, error=%s, record=%s",
                     qname, DkimStatus_getSymbol(build_stat), NNSTR(txtrecord));
                DnsTxtResponse_free(txt_rr);
                return build_stat;
            } else if (DSTAT_ISPERMFAIL(build_stat)) {
                LogDebug
                    ("ATPS record candidate discarded due to syntax error(s): domain=%s, error=%s, record=%s",
                     qname, DkimStatus_getSymbol(build_stat), NNSTR(txtrecord));
            } else {
                LogNotice("DkimAtps_build failed: domain=%s, error=%s, record=%s",
                          qname, DkimStatus_getSymbol(build_stat), NNSTR(txtrecord));
            }   // end if
        }   // end for
        DnsTxtResponse_free(txt_rr);
        txt_rr = NULL;
        // fallthrough

    case DNS_STAT_NODATA:
    case DNS_STAT_NOVALIDANSWER:
    case DNS_STAT_NXDOMAIN:
        /*
         * [RFC6541] 4.4.
         * o  No answer is returned (i.e., [DNS] reply code NXDOMAIN, or NOERROR
         *    with no answers), or one or more answers have been returned as
         *    described above but none contain a valid ATPS reply.  In this
         *    case, the Signer has not been authorized to act as a third-party
         *    Signer for this ADMD, and thus the Verifier MUST continue to the
         *    next query, if any.
         */
        LogDebug("No valid ATPS records are found on DNS: qname=%s", qname);
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
         * [RFC6541] 4.4.
         * o  An error is returned (i.e., any other [DNS] reply code).  It is no
         *    longer possible to determine whether or not this message satisfies
         *    the ADMD's list of authorized third-party Signers.  The Verifier
         *    SHOULD stop processing and defer the message for later processing,
         *    such as requesting a temporary failure code from the Mail Transfer
         *    Agent (MTA).
         */
        LogDnsError("txt", qname, "DKIM ATPS record", DnsResolver_getErrorSymbol(resolver));
        return DSTAT_TMPERR_DNS_ERROR_RESPONSE;

    case DNS_STAT_SYSTEM:
        DkimLogSysError("System error occurred on DNS lookup: rrtype=txt, qname=%s, error=%s",
                        qname, DnsResolver_getErrorSymbol(resolver));
        return DSTAT_SYSERR_DNS_LOOKUP_FAILURE;

    case DNS_STAT_NOMEMORY:
        LogNoResource();
        return DSTAT_SYSERR_NORESOURCE;

    case DNS_STAT_BADREQUEST:
    default:
        DkimLogImplError
            ("DnsResolver_lookupTxt returns unexpected value: value=0x%x, rrtype=txt, qname=%s",
             txtquery_stat, qname);
        return DSTAT_SYSERR_IMPLERROR;
    }   // end switch
}   // end function: DkimAtps_query

/**
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_PERMFAIL_UNSUPPORTED_HASH_ALGORITHM
 * @error DSTAT_SYSERR_DIGEST_UPDATE_FAILURE
 * @error DSTAT_SYSERR_NORESOURCE
 */
static DkimStatus
DkimAtps_appendHashedSdid(const char *sdid, DkimHashAlgorithm hashalg, XBuffer *xbuf)
{
    size_t sdid_len = strlen(sdid);
    char sdid_lower[sdid_len + 1];
    _strlowercpy(sdid_lower, sdid, sdid_len + 1);

    const EVP_MD *digest_alg = NULL;
    switch (hashalg) {
    case DKIM_HASH_ALGORITHM_SHA1:
        digest_alg = EVP_sha1();
        break;
    case DKIM_HASH_ALGORITHM_SHA256:
        digest_alg = EVP_sha256();
        break;
    default:
        return DSTAT_PERMFAIL_UNSUPPORTED_HASH_ALGORITHM;
    }   // end switch

    unsigned int digestbuflen = EVP_MD_size(digest_alg);
    unsigned char digestbuf[digestbuflen];

    if (0 == EVP_Digest(sdid_lower, sdid_len, digestbuf, &digestbuflen, digest_alg, NULL)) {
        DkimLogSysError("EVP_Digest failed");
        OpenSSL_logErrors();
        return DSTAT_SYSERR_DIGEST_UPDATE_FAILURE;
    }   // end if

    return DkimConverter_encodeBaseX32(digestbuf, digestbuflen, xbuf);
}   // end function: DkimAtps_appendHashedSdid

/**
 * @error DSTAT_INFO_DNSRR_NXDOMAIN Author Domain does not exist (NXDOMAIN)
 * @error DSTAT_INFO_DNSRR_NOT_EXIST ATPS record have not found
 * @error DSTAT_TMPERR_DNS_ERROR_RESPONSE DNS lookup error (received error response)
 * @error DSTAT_SYSERR_DNS_LOOKUP_FAILURE DNS lookup error (failed to lookup itself)
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 * @error DSTAT_SYSERR_IMPLERROR obvious implementation error
 * @error DSTAT_SYSERR_DIGEST_UPDATE_FAILURE error on digest calculation (returned by OpenSSL EVP_Digest())
 */
DkimStatus
DkimAtps_lookup(const char *atps_domain, const char *sdid,
                DkimHashAlgorithm hashalg, DnsResolver *resolver, DkimAtps **atps_record)
{
    assert(NULL != atps_domain);
    assert(NULL != sdid);
    assert(NULL != resolver);

    XBuffer *xbuf = XBuffer_new(0);
    switch (hashalg) {
    case DKIM_HASH_ALGORITHM_SHA1:
    case DKIM_HASH_ALGORITHM_SHA256:;
        DkimStatus dstat = DkimAtps_appendHashedSdid(sdid, hashalg, xbuf);
        if (DSTAT_OK != dstat) {
            XBuffer_free(xbuf);
            return dstat;
        }   // end if
        break;

    case DKIM_HASH_ALGORITHM_NONE:
        XBuffer_appendString(xbuf, sdid);
        break;

    default:
        DkimLogImplError("unsupported hash algorithm for ATPS domain name hashing: value=0x%x",
                         hashalg);
        XBuffer_free(xbuf);
        return DSTAT_SYSERR_IMPLERROR;
    }   // end switch

    XBuffer_appendString(xbuf, "." DKIM_DNS_ATPS_SELECTOR ".");
    XBuffer_appendString(xbuf, atps_domain);

    if (0 != XBuffer_status(xbuf)) {
        XBuffer_free(xbuf);
        LogNoResource();
        return DSTAT_SYSERR_NORESOURCE;
    }   // end if

    DkimStatus dstat = DkimAtps_query(resolver, XBuffer_getString(xbuf), sdid, atps_record);
    XBuffer_free(xbuf);
    return dstat;
}   // end function: DkimAtps_lookup

////////////////////////////////////////////////////////////////////////
// accessor

const char *
DkimAtps_getDomain(const DkimAtps *self)
{
    return self->domain;
}   // end function: DkimAtps_getDomain
