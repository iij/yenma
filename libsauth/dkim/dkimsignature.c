/*
 * Copyright (c) 2006-2016 Internet Initiative Japan Inc. All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <time.h>
#include <stdbool.h>
#include <errno.h>

#include "loghandler.h"
#include "dkimlogger.h"
#include "ptrop.h"
#include "pstring.h"
#include "xbuffer.h"
#include "xskip.h"
#include "xparse.h"
#include "foldstring.h"
#include "intarray.h"
#include "inetdomain.h"
#include "inetmailbox.h"

#include "dkim.h"
#include "dkimspec.h"
#include "dkimenum.h"
#include "dkimtaglistobject.h"
#include "dkimconverter.h"
#include "dkimsignature.h"

#define DKIM_SIGNATURE_HEADER_WIDTH  78

struct DkimSignature {
    DkimTagListObject_MEMBER;
    char *rawname;              // DKIM-Signature header field name (is normally "DKIM-Signature")
    char *rawvalue;             // DKIM-Signature header field value
    const char *raw_value_b_head;   // pointer to the head of sig-b-tag of "rawvalue" field
    const char *raw_value_b_tail;   // pointer to the tail of sig-b-tag of "rawvalue" field
    time_t verification_time;   // verification timestamp to compare with sig-t-tag and sig-x-tag
    DkimKeyType keytype;        // sig-a-tag-k
    DkimHashAlgorithm hashalg;  // sig-a-tag-h
    XBuffer *signature_value;   // sig-b-tag
    XBuffer *bodyhash;          // sig-bh-tag
    StrArray *signed_header_fields; // sig-h-tag
    DkimC14nAlgorithm headercanon;  // sig-c-tag
    DkimC14nAlgorithm bodycanon;    // sig-c-tag
    long long signing_timestamp;    // sig-t-tag
    long long expiration_date;  // sig-x-tag
    long long body_length_limit;    // sig-l-tag, -1 for unlimited
    char *selector;             // sig-s-tag
    char *sdid;                 // sig-d-tag
    InetMailbox *auid;          // sig-i-tag
    IntArray *querymethod;      // sig-q-tag (DkimQueryMethod)
    char *atps_domain;          // dkim-atps-tag
    DkimHashAlgorithm atps_hashalg; // dkim-atpsh-tag
};

static DkimStatus DkimSignature_parse_v(DkimTagListObject *base,
                                        const DkimTagParseContext *context, const char **nextp);
static DkimStatus DkimSignature_parse_a(DkimTagListObject *base,
                                        const DkimTagParseContext *context, const char **nextp);
static DkimStatus DkimSignature_parse_b(DkimTagListObject *base,
                                        const DkimTagParseContext *context, const char **nextp);
static DkimStatus DkimSignature_parse_bh(DkimTagListObject *base,
                                         const DkimTagParseContext *context, const char **nextp);
static DkimStatus DkimSignature_parse_c(DkimTagListObject *base,
                                        const DkimTagParseContext *context, const char **nextp);
static DkimStatus DkimSignature_parse_d(DkimTagListObject *base,
                                        const DkimTagParseContext *context, const char **nextp);
static DkimStatus DkimSignature_parse_h(DkimTagListObject *base,
                                        const DkimTagParseContext *context, const char **nextp);
static DkimStatus DkimSignature_parse_i(DkimTagListObject *base,
                                        const DkimTagParseContext *context, const char **nextp);
static DkimStatus DkimSignature_parse_l(DkimTagListObject *base,
                                        const DkimTagParseContext *context, const char **nextp);
static DkimStatus DkimSignature_parse_q(DkimTagListObject *base,
                                        const DkimTagParseContext *context, const char **nextp);
static DkimStatus DkimSignature_parse_s(DkimTagListObject *base,
                                        const DkimTagParseContext *context, const char **nextp);
static DkimStatus DkimSignature_parse_t(DkimTagListObject *base,
                                        const DkimTagParseContext *context, const char **nextp);
static DkimStatus DkimSignature_parse_x(DkimTagListObject *base,
                                        const DkimTagParseContext *context, const char **nextp);
static DkimStatus DkimSignature_parse_atps(DkimTagListObject *base,
                                           const DkimTagParseContext *context, const char **nextp);
static DkimStatus DkimSignature_parse_atpsh(DkimTagListObject *base,
                                            const DkimTagParseContext *context, const char **nextp);

static const DkimTagListObjectFieldMap dkim_signature_field_table[] = {
    {"v", DkimSignature_parse_v, true, NULL},
    {"a", DkimSignature_parse_a, true, NULL},
    {"b", DkimSignature_parse_b, true, NULL},
    {"bh", DkimSignature_parse_bh, true, NULL},
    {"c", DkimSignature_parse_c, false, "simple/simple"},
    {"d", DkimSignature_parse_d, true, NULL},
    {"h", DkimSignature_parse_h, true, NULL},
    {"i", DkimSignature_parse_i, false, NULL},
    {"l", DkimSignature_parse_l, false, NULL},
    {"q", DkimSignature_parse_q, false, "dns/txt"},
    {"s", DkimSignature_parse_s, true, NULL},
    {"t", DkimSignature_parse_t, false, NULL},
    {"x", DkimSignature_parse_x, false, NULL},
    {"z", NULL, false, NULL},
    {"atps", DkimSignature_parse_atps, false, NULL},
    {"atpsh", DkimSignature_parse_atpsh, false, NULL},
    {NULL, NULL, false, NULL},  // sentinel
};

////////////////////////////////////////////////////////////////////////
// private functions

/*
 * [RFC6376] 3.5.
 * sig-v-tag       = %x76 [FWS] "=" [FWS] 1*DIGIT
 */
DkimStatus
DkimSignature_parse_v(DkimTagListObject *base __attribute__((unused)),
                      const DkimTagParseContext *context, const char **nextp)
{
    /*
     * [RFC6376] 3.5.
     * It MUST have the value "1" for implementations compliant with this version of DKIM.
     */
    static const char *acceptable_dkim_versions[] = {
        "1", NULL,
    };

    for (const char **val = acceptable_dkim_versions; NULL != *val; ++val) {
        if (0 < XSkip_string(context->value_head, context->value_tail, *val, nextp)) {
            return DSTAT_OK;
        }   // end if
    }   // end for

    *nextp = context->value_head;
    /*
     * [RFC6376] 6.1.1.
     * Verifiers MUST return PERMFAIL (incompatible version)
     * when presented a DKIM-Signature header field with a "v=" tag that is
     * inconsistent with this specification.
     */
    DkimLogPermFail("unsupported signature version: near %.50s", context->value_head);
    return DSTAT_PERMFAIL_SIGNATURE_INCOMPATIBLE_VERSION;
}   // end function: DkimSignature_parse_v

/*
 * [RFC6376] 3.5.
 * sig-a-tag       = %x61 [FWS] "=" [FWS] sig-a-tag-alg
 * sig-a-tag-alg   = sig-a-tag-k "-" sig-a-tag-h
 * sig-a-tag-k     = "rsa" / x-sig-a-tag-k
 * sig-a-tag-h     = "sha1" / "sha256" / x-sig-a-tag-h
 * x-sig-a-tag-k   = ALPHA *(ALPHA / DIGIT)
 *                      ; for later extension
 * x-sig-a-tag-h   = ALPHA *(ALPHA / DIGIT)
 *                      ; for later extension
 */
DkimStatus
DkimSignature_parse_a(DkimTagListObject *base, const DkimTagParseContext *context,
                      const char **nextp)
{
    DkimSignature *self = (DkimSignature *) base;
    const char *p = context->value_head;
    const char *tailp;

    SETDEREF(nextp, context->value_head);
    if (0 >= XSkip_alphaAlnum(p, context->value_tail, &tailp)) {
        DkimLogPermFail("no value for sig-a-tag-k: near %.50s", context->value_head);
        return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
    }   // end if

    self->keytype = DkimEnum_lookupKeyTypeByNameSlice(p, tailp);
    if (DKIM_KEY_TYPE_NULL == self->keytype) {
        DkimLogPermFail("unsupported public key algorithm: near %.50s", context->value_head);
        return DSTAT_PERMFAIL_UNSUPPORTED_KEY_ALGORITHM;
    }   // end if

    if (0 >= XSkip_char(p = tailp, context->value_tail, '-', &p)) {
        DkimLogPermFail("hyphen missing for sig-a-tag: near %.50s", context->value_head);
        return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
    }   // end if

    if (0 >= XSkip_alphaAlnum(p, context->value_tail, &tailp)) {
        DkimLogPermFail("no value for sig-a-tag-h: near %.50s", context->value_head);
        return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
    }   // end if

    self->hashalg = DkimEnum_lookupHashAlgorithmByNameSlice(p, tailp);
    if (DKIM_HASH_ALGORITHM_NULL == self->hashalg) {
        DkimLogPermFail("unsupported digest algorithm: near %.50s", context->value_head);
        return DSTAT_PERMFAIL_UNSUPPORTED_HASH_ALGORITHM;
    }   // end if

    SETDEREF(nextp, tailp);
    return DSTAT_OK;
}   // end function: DkimSignature_parse_a

/*
 * [RFC6376] 3.5.
 * sig-b-tag       = %x62 [FWS] "=" [FWS] sig-b-tag-data
 * sig-b-tag-data  = base64string
 */
DkimStatus
DkimSignature_parse_b(DkimTagListObject *base, const DkimTagParseContext *context,
                      const char **nextp)
{
    DkimSignature *self = (DkimSignature *) base;
    const char *p = context->value_head;

    if (NULL != self->signature_value) {
        DkimLogImplError("sig-b-tag already set");
        return DSTAT_SYSERR_IMPLERROR;
    }   // end if

    SETDEREF(nextp, context->value_head);
    XSkip_fws(p, context->value_tail, &p);
    if (context->value_tail <= p) {
        // empty value
        DkimLogPermFail("sig-b-tag has empty value: near %.50s", context->value_head);
        return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
    }   // end if

    DkimStatus decode_stat;
    self->signature_value = DkimConverter_decodeBase64(p, context->value_tail, &p, &decode_stat);
    if (NULL == self->signature_value) {
        return decode_stat;
    }   // end if

    self->raw_value_b_head = context->value_head;
    self->raw_value_b_tail = context->value_tail;
    SETDEREF(nextp, p);
    return DSTAT_OK;
}   // end function: DkimSignature_parse_b

/*
 * [RFC6376] 3.5.
 * sig-bh-tag      = %x62 %x68 [FWS] "=" [FWS] sig-bh-tag-data
 * sig-bh-tag-data = base64string
 */
DkimStatus
DkimSignature_parse_bh(DkimTagListObject *base, const DkimTagParseContext *context,
                       const char **nextp)
{
    DkimSignature *self = (DkimSignature *) base;
    const char *p = context->value_head;

    if (self->bodyhash) {
        DkimLogImplError("sig-bh-tag already set");
        return DSTAT_SYSERR_IMPLERROR;
    }   // end if

    SETDEREF(nextp, context->value_head);
    XSkip_fws(p, context->value_tail, &p);
    if (context->value_tail <= p) {
        // empty value
        DkimLogPermFail("sig-bh-tag has empty value: near %.50s", context->value_head);
        return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
    }   // end if

    DkimStatus decode_stat;
    self->bodyhash =
        DkimConverter_decodeBase64(context->value_head, context->value_tail, &p, &decode_stat);
    if (NULL == self->bodyhash) {
        return decode_stat;
    }   // end if

    SETDEREF(nextp, p);
    return DSTAT_OK;
}   // end function: DkimSignature_parse_bh

/*
 * [RFC6376] 3.5.
 * sig-c-tag       = %x63 [FWS] "=" [FWS] sig-c-tag-alg
 *                   ["/" sig-c-tag-alg]
 * sig-c-tag-alg   = "simple" / "relaxed" / x-sig-c-tag-alg
 * x-sig-c-tag-alg = hyphenated-word    ; for later extension
 */
DkimStatus
DkimSignature_parse_c(DkimTagListObject *base, const DkimTagParseContext *context,
                      const char **nextp)
{
    DkimSignature *self = (DkimSignature *) base;
    const char *p = context->value_head;
    const char *tailp;

    SETDEREF(nextp, context->value_head);
    if (0 >= XSkip_hyphenatedWord(p, context->value_tail, &tailp)) {
        DkimLogPermFail("no value for header canonicalization algorithm: near %.50s",
                        context->value_head);
        return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
    }   // end if

    self->headercanon = DkimEnum_lookupC14nAlgorithmByNameSlice(p, tailp);
    if (DKIM_C14N_ALGORITHM_NULL == self->headercanon) {
        DkimLogPermFail("unsupported header canonicalization algorithm: near %.50s",
                        context->value_head);
        return DSTAT_PERMFAIL_UNSUPPORTED_C14N_ALGORITHM;
    }   // end if

    if (0 >= XSkip_char(p = tailp, context->value_tail, '/', &p)) {
        /*
         * [RFC6376] 3.5.
         * If only one algorithm is named, that algorithm is used for the header
         * and "simple" is used for the body.  For example, "c=relaxed" is
         * treated the same as "c=relaxed/simple".
         */
        self->bodycanon = DKIM_C14N_ALGORITHM_SIMPLE;
    } else {
        if (0 >= XSkip_hyphenatedWord(p, context->value_tail, &tailp)) {
            DkimLogPermFail("no value for body canonicalization algorithm: near %.50s",
                            context->value_head);
            return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
        }   // end if

        self->bodycanon = DkimEnum_lookupC14nAlgorithmByNameSlice(p, tailp);
        if (DKIM_C14N_ALGORITHM_NULL == self->bodycanon) {
            DkimLogPermFail("unsupported body canonicalization algorithm: near %.50s",
                            context->value_head);
            return DSTAT_PERMFAIL_UNSUPPORTED_C14N_ALGORITHM;
        }   // end if
    }   // end if

    SETDEREF(nextp, tailp);
    return DSTAT_OK;
}   // end function: DkimSignature_parse_c

/*
 * [RFC6376] 3.5.
 * sig-d-tag       = %x64 [FWS] "=" [FWS] domain-name
 * domain-name     = sub-domain 1*("." sub-domain)
 *                   ; from [RFC5321] Domain,
 *                   ; excluding address-literal
 */
DkimStatus
DkimSignature_parse_d(DkimTagListObject *base, const DkimTagParseContext *context,
                      const char **nextp)
{
    DkimSignature *self = (DkimSignature *) base;

    // Does value match domain-name?
    if (0 >= XSkip_domainName(context->value_head, context->value_tail, nextp)) {
        DkimLogPermFail("sig-d-tag doesn't match domain-name: near %.50s", context->value_head);
        return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
    }   // end if

    self->sdid = strpdup(context->value_head, *nextp);
    if (NULL == self->sdid) {
        LogNoResource();
        return DSTAT_SYSERR_NORESOURCE;
    }   // end if

    return DSTAT_OK;
}   // end function: DkimSignature_parse_d

/*
 * [RFC6376] 3.5.
 * sig-h-tag       = %x68 [FWS] "=" [FWS] hdr-name
 *                    *( [FWS] ":" [FWS] hdr-name )
 * [RFC6376] 2.10.
 * hdr-name        =  field-name
 */
DkimStatus
DkimSignature_parse_h(DkimTagListObject *base, const DkimTagParseContext *context,
                      const char **nextp)
{
    DkimSignature *self = (DkimSignature *) base;
    const char *p = context->value_head;
    const char *tailp;

    SETDEREF(nextp, context->value_head);
    do {
        XSkip_fws(p, context->value_tail, &p);
        if (0 >= XSkip_fieldName(p, context->value_tail, &tailp)) {
            DkimLogPermFail("hdr-name missing: near %.50s", context->value_head);
            return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
        }   // end if
        // TODO: Does upper limit need to prevent DoS?
        if (0 > StrArray_appendWithLength(self->signed_header_fields, p, tailp - p)) {
            LogNoResource();
            return DSTAT_SYSERR_NORESOURCE;
        }   // end if
        XSkip_fws(tailp, context->value_tail, &p);
    } while (0 < XSkip_char(p, context->value_tail, ':', &p));

    SETDEREF(nextp, p);
    return DSTAT_OK;
}   // end function: DkimSignature_parse_h

/*
 * [RFC6376] 3.5.
 * sig-i-tag       = %x69 [FWS] "=" [FWS] [ Local-part ]
 *                            "@" domain-name
 *
 * [RFC6376] 3.5.
 * i= The Agent or User Identifier (AUID) on behalf of which the SDID is
 *    taking responsibility (dkim-quoted-printable; OPTIONAL, default is
 *    an empty local-part followed by an "@" followed by the domain from
 *    the "d=" tag).
 *
 *    The syntax is a standard email address where the local-part MAY be
 *    omitted.  The domain part of the address MUST be the same as, or a
 *    subdomain of, the value of the "d=" tag.
 */
DkimStatus
DkimSignature_parse_i(DkimTagListObject *base, const DkimTagParseContext *context,
                      const char **nextp)
{
    DkimSignature *self = (DkimSignature *) base;
    const char *errptr = NULL;

    if (NULL != self->auid) {
        DkimLogImplError("sig-i-tag already set");
        return DSTAT_SYSERR_IMPLERROR;
    }   // end if

    // First, decode dkim-quoted-printable to plain text.
    XBuffer *decoded_auid = XBuffer_new(0);
    if (NULL == decoded_auid) {
        LogNoResource();
        return DSTAT_SYSERR_NORESOURCE;
    }   // end if

    (void) XParse_dkimQuotedPrintable(context->value_head, context->value_tail, nextp,
                                      decoded_auid);
    if (0 != XBuffer_status(decoded_auid)) {
        XBuffer_free(decoded_auid);
        LogNoResource();
        return DSTAT_SYSERR_NORESOURCE;
    }   // end if

    // parse in accordance with ABNF of sig-i-tag
    const char *auid_head = XBuffer_getString(decoded_auid);
    const char *auid_tail = auid_head + XBuffer_getSize(decoded_auid);
    const char *parsed_tail;
    self->auid = InetMailbox_buildDkimIdentity(auid_head, auid_tail, &parsed_tail, &errptr);
    XBuffer_free(decoded_auid);
    if (NULL == self->auid && NULL == errptr) {
        // Memory allocation error
        *nextp = context->value_head;
        LogNoResource();
        return DSTAT_SYSERR_NORESOURCE;
    } else if (NULL == self->auid || parsed_tail != auid_tail) {
        // parsing error
        *nextp = context->value_head;
        InetMailbox_free(self->auid);
        self->auid = NULL;
        DkimLogPermFail("sig-i-tag doesn't match identity: near %.50s", context->value_head);
        return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
    }   // end if

    return DSTAT_OK;
}   // end function: DkimSignature_parse_i

/*
 * [RFC6376] 3.5.
 * sig-l-tag    = %x6c [FWS] "=" [FWS]
 *                1*76DIGIT
 */
DkimStatus
DkimSignature_parse_l(DkimTagListObject *base, const DkimTagParseContext *context,
                      const char **nextp)
{
    DkimSignature *self = (DkimSignature *) base;
    self->body_length_limit =
        DkimConverter_longlong(context->value_head, context->value_tail, DKIM_SIG_L_TAG_LEN, nextp);
    // SPEC: signature whose sig-l-tag is greater than or equal to 2^63 are not supported.
    if (0 <= self->body_length_limit && context->value_tail == *nextp) {
        return DSTAT_OK;
    } else {
        DkimLogPermFail("sig-l-tag has invalid line length limit: near %.50s", context->value_head);
        return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
    }   // end if
}   // end function: DkimSignature_parse_l

/*
 * [RFC6376] 3.5.
 * sig-q-tag        = %x71 [FWS] "=" [FWS] sig-q-tag-method
 *                       *([FWS] ":" [FWS] sig-q-tag-method)
 * sig-q-tag-method = "dns/txt" / x-sig-q-tag-type
 *                    ["/" x-sig-q-tag-args]
 * x-sig-q-tag-type = hyphenated-word  ; for future extension
 * x-sig-q-tag-args = qp-hdr-value
 * [RFC6376] 2.10.
 * qp-hdr-value    =  dkim-quoted-printable    ; with "|" encoded
 */
DkimStatus
DkimSignature_parse_q(DkimTagListObject *base, const DkimTagParseContext *context,
                      const char **nextp)
{
    DkimSignature *self = (DkimSignature *) base;
    const char *p = context->value_head;
    const char *typehead, *typetail;

    SETDEREF(nextp, context->value_head);
    do {
        XSkip_fws(p, context->value_tail, &typehead);

        if (0 >= XSkip_hyphenatedWord(typehead, context->value_tail, &typetail)) {
            DkimLogPermFail("no value for sig-q-tag-method: near %.50s", context->value_head);
            return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
        }   // end if
        if (0 < XSkip_char(typetail, context->value_tail, '/', &typetail)) {
            /*
             * NOTE: To parse x-sig-q-tag-args, it should be interpreted
             * as not hyphenated-word but dkim-quoted-printable.
             * If query methods needs dkim-quoted-printable to parse are defined, this should be fixed.
             */
            if (0 >= XSkip_hyphenatedWord(typetail, context->value_tail, &typetail)) {
                DkimLogPermFail("no value for x-sig-q-tag-args: near %.50s", context->value_head);
                return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
            }   // end if
        }   // end if

        DkimQueryMethod keyretr_method = DkimEnum_lookupQueryMethodByNameSlice(typehead, typetail);
        /*
         * [RFC6376] 3.5.
         * Unrecognized query mechanisms MUST be ignored.
         */
        if (keyretr_method != DKIM_QUERY_METHOD_NULL) {
            // check not to register "keyretr_method" repeatedly to prevent DoS attack
            if (0 > IntArray_linearSearch(self->querymethod, keyretr_method)) {
                if (0 > IntArray_append(self->querymethod, keyretr_method)) {
                    LogNoResource();
                    return DSTAT_SYSERR_NORESOURCE;
                }   // end if
            }   // end if
        }   // end if

        SETDEREF(nextp, typetail);
        XSkip_fws(typetail, context->value_tail, &p);
    } while (0 < XSkip_char(p, context->value_tail, ':', &p));

    if (0 == IntArray_getCount(self->querymethod)) {
        DkimLogPermFail("no public key retrieving methods are available: near %.50s",
                        context->value_head);
        return DSTAT_PERMFAIL_UNSUPPORTED_QUERY_METHOD;
    }   // end if

    return DSTAT_OK;
}   // end function: DkimSignature_parse_q

/*
 * [RFC6376] 3.5.
 * sig-s-tag    = %x73 [FWS] "=" [FWS] selector
 * [RFC6376] 3.1.
 * selector =   sub-domain *( "." sub-domain )
 */
DkimStatus
DkimSignature_parse_s(DkimTagListObject *base, const DkimTagParseContext *context,
                      const char **nextp)
{
    DkimSignature *self = (DkimSignature *) base;

    if (0 >= XSkip_selector(context->value_head, context->value_tail, nextp)) {
        DkimLogPermFail("sig-s-tag doesn't match selector: near %.50s", context->value_head);
        return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
    }   // end if

    self->selector = strpdup(context->value_head, *nextp);
    if (NULL == self->selector) {
        LogNoResource();
        return DSTAT_SYSERR_NORESOURCE;
    }   // end if

    return DSTAT_OK;
}   // end function: DkimSignature_parse_s

/*
 * [RFC6376] 3.5.
 * sig-t-tag    = %x74 [FWS] "=" [FWS] 1*12DIGIT
 */
DkimStatus
DkimSignature_parse_t(DkimTagListObject *base, const DkimTagParseContext *context,
                      const char **nextp)
{
    DkimSignature *self = (DkimSignature *) base;
    self->signing_timestamp =
        DkimConverter_longlong(context->value_head, context->value_tail, DKIM_SIG_T_TAG_LEN, nextp);
    if (0 <= self->signing_timestamp && context->value_tail == *nextp) {
        return DSTAT_OK;
    } else {
        DkimLogPermFail("sig-t-tag has invalid timestamp: near %.50s", context->value_head);
        return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
    }   // end if
}   // end function: DkimSignature_parse_t

/*
 * [RFC6376] 3.5.
 * sig-x-tag    = %x78 [FWS] "=" [FWS]
 *                               1*12DIGIT
 */
DkimStatus
DkimSignature_parse_x(DkimTagListObject *base, const DkimTagParseContext *context,
                      const char **nextp)
{
    DkimSignature *self = (DkimSignature *) base;
    self->expiration_date =
        DkimConverter_longlong(context->value_head, context->value_tail, DKIM_SIG_X_TAG_LEN, nextp);
    if (0 <= self->expiration_date && context->value_tail == *nextp) {
        return DSTAT_OK;
    } else {
        DkimLogPermFail("sig-x-tag has invalid timestamp: near %.50s", context->value_head);
        return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
    }   // end if
}   // end function: DkimSignature_parse_x

/*
 * [RFC6376] 3.5.
 * sig-z-tag      = %x7A [FWS] "=" [FWS] sig-z-tag-copy
 *                  *( "|" [FWS] sig-z-tag-copy )
 * sig-z-tag-copy = hdr-name [FWS] ":" qp-hdr-value
 * [RFC6376] 2.10.
 * hdr-name        =  field-name
 * qp-hdr-value    =  dkim-quoted-printable    ; with "|" encoded
 *
 * Ignore sig-z-tag entirely.
 * This tag has no concern with verification process.
 */

/*
 * [RFC6541] 4.2.
 * dkim-atps-tag = %x61.74.70.73 *WSP "=" *WSP domain-name
 */
DkimStatus
DkimSignature_parse_atps(DkimTagListObject *base, const DkimTagParseContext *context,
                         const char **nextp)
{
    DkimSignature *self = (DkimSignature *) base;

    if (0 >= XSkip_domainName(context->value_head, context->value_tail, nextp)) {
        DkimLogPermFail("dkim-atps-tag doesn't match domain-name: near %.50s", context->value_head);
        return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
    }   // end if

    self->atps_domain = strpdup(context->value_head, *nextp);
    if (NULL == self->atps_domain) {
        LogNoResource();
        return DSTAT_SYSERR_NORESOURCE;
    }   // end if

    return DSTAT_OK;
}   // end function: DkimSignature_parse_atps

/*
 * [RFC6541] 4.2.
 * dkim-atpsh-tag = %x61.74.70.73.68 *WSP "=" *WSP
 *                  ( "none" / key-h-tag-alg )
 */
DkimStatus
DkimSignature_parse_atpsh(DkimTagListObject *base, const DkimTagParseContext *context,
                          const char **nextp)
{
    DkimSignature *self = (DkimSignature *) base;
    DkimHashAlgorithm digestalg =
        DkimEnum_lookupAtpsHashAlgorithmByNameSlice(context->value_head, context->value_tail);
    if (DKIM_HASH_ALGORITHM_NULL != digestalg) {
        self->atps_hashalg = digestalg;
        SETDEREF(nextp, context->value_tail);
        return DSTAT_OK;
    } else {
        DkimLogPermFail("dkim-atpsh-tag doesn't match key-h-tag-alg: near %.50s",
                        context->value_head);
        return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
    }   // end if
}   // end function: DkimSignature_parse_atpsh

////////////////////////////////////////////////////////////////////////
// public functions

/**
 * create DkimSignature object
 * @return initialized DkimSignature object, or NULL if memory allocation failed.
 */
DkimSignature *
DkimSignature_new(void)
{
    DkimSignature *self = (DkimSignature *) malloc(sizeof(DkimSignature));
    if (NULL == self) {
        return NULL;
    }   // end if
    memset(self, 0, sizeof(DkimSignature));

    self->signed_header_fields = StrArray_new(0);
    if (NULL == self->signed_header_fields) {
        goto cleanup;
    }   // end if
    self->querymethod = IntArray_new(0);
    if (NULL == self->querymethod) {
        goto cleanup;
    }   // end if
    self->ftbl = dkim_signature_field_table;
    self->signing_timestamp = -1LL;
    self->expiration_date = -1LL;
    self->body_length_limit = -1LL;

    return self;

  cleanup:
    DkimSignature_free(self);
    return NULL;
}   // end function: DkimSignature_new

/*
 * Validate the signature semantically.
 * validates as described in [RFC6376] 6.1.1. except expiration
 * (which is delegated to DkimSignature_isExpired())
 */
static DkimStatus
DkimSignature_validate(DkimSignature *self)
{
    /*
     * check whether From header field is included in the list of signed header fields.
     * [RFC6376] 6.1.1.
     * If the "h=" tag does not include the From header field, the Verifier
     * MUST ignore the DKIM-Signature header field and return PERMFAIL (From
     * field not signed).
     */
    if (!DkimSignature_isHeaderSigned(self, FROMHEADER)) {
        DkimLogPermFail("sig-h-tag doesn't include " FROMHEADER " header");
        return DSTAT_PERMFAIL_FROM_FIELD_NOT_SIGNED;
    }   // end if

    if (0 > time(&(self->verification_time))) {
        DkimLogImplError("time(2) failed: errno=%s", strerror(errno));
        return DSTAT_SYSERR_IMPLERROR;
    }   // end if

    // check consistency between timestamp (sig-t-tag) and expiration date (sig-x-tag)
    if (0LL < self->signing_timestamp && 0LL < self->expiration_date
        && self->expiration_date < self->signing_timestamp) {
        DkimLogPermFail("signature timestamp has discrepancy: timestamp=%lld, expire=%lld",
                        self->signing_timestamp, self->expiration_date);
        return DSTAT_PERMFAIL_INCONSISTENT_TIMESTAMP;
    }   // end if

    // arrange AUID (sig-i-tag)
    if (NULL != self->auid) {
        /*
         * confirm that SDID (sig-d-tag) is the same as or a parent domain of
         * the domain part of AUID (sig-i-tag) if sig-i-tag is included in the signature.
         *
         * [RFC6376] 6.1.1.
         * Verifiers MUST confirm that the domain specified in the "d=" tag is
         * the same as or a parent domain of the domain part of the "i=" tag.
         * If not, the DKIM-Signature header field MUST be ignored, and the
         * Verifier should return PERMFAIL (domain mismatch).
         */
        if (!InetDomain_isParent(self->sdid, InetMailbox_getDomain(self->auid))) {
            DkimLogPermFail
                ("sig-d-tag and sig-i-tag domain mismatch: sig-d-tag=%s, sig-i-tag-domain=%s",
                 self->sdid, InetMailbox_getDomain(self->auid));
            return DSTAT_PERMFAIL_DOMAIN_MISMATCH;
        }   // end if
    } else {
        /*
         * build AUID (sig-i-tag) from empty local-part and SDID (sig-d-tag)
         * if sig-i-tag is not included in the signature.
         *
         * [RFC6376] 6.1.1.
         * If the DKIM-Signature header field does not contain the "i=" tag, the
         * Verifier MUST behave as though the value of that tag were "@d", where
         * "d" is the value from the "d=" tag.
         */
        self->auid = InetMailbox_build("", self->sdid);
        if (NULL == self->auid) {
            LogNoResource();
            return DSTAT_SYSERR_NORESOURCE;
        }   // end if
    }   // end if

    return DSTAT_OK;
}   // end function: DkimSignature_validate

/**
 * Check whether or not the signature has expired.
 * @return DSTAT_OK if the signature is valid, DSTAT_PERMFAIL_SIGNATURE_EXPIRED if expired.
 */
DkimStatus
DkimSignature_isExpired(const DkimSignature *self)
{
    /*
     * [RFC6376] 6.1.1.
     * Verifiers MAY ignore the DKIM-Signature header field and return
     * PERMFAIL (signature expired) if it contains an "x=" tag and the
     * signature has expired.
     */
    if (0LL < self->expiration_date && self->expiration_date < self->verification_time) {
        DkimLogPermFail("signature has expired: expire=%lld, now=%ld",
                        self->expiration_date, self->verification_time);
        return DSTAT_PERMFAIL_SIGNATURE_EXPIRED;
    }   // end if
    return DSTAT_OK;
}   // end function: DkimSignature_isExpired

/**
 * Check whether the signature has a future timestamp
 * @return DSTAT_OK if the timestamp is valid, DSTAT_PERMFAIL_INCONSISTENT_TIMESTAMP if invalid.
 */
DkimStatus
DkimSignature_checkFutureTimestamp(const DkimSignature *self, time_t max_clock_skew)
{
    /*
     * treats DKIM signatures signed in the future as invalid (PERMFAIL)
     * [RFC6376] 3.5.
     * Implementations MAY ignore signatures that have a
     * timestamp in the future.
     */
    if (0LL < self->signing_timestamp
        && (long long) self->verification_time + (long long) max_clock_skew < self->signing_timestamp) {
        DkimLogPermFail("this signature had signed in the future: timestamp=%lld, now=%ld",
                        self->signing_timestamp, self->verification_time);
        return DSTAT_PERMFAIL_INCONSISTENT_TIMESTAMP;
    }   // end if
    return DSTAT_OK;
}   // end function: DkimSignature_checkFutureTimestamp

/**
 * build DkimSignature object from header field.
 */
DkimStatus
DkimSignature_build(const char *headerf, const char *headerv, DkimSignature **signature)
{
    DkimSignature *self = DkimSignature_new();
    if (NULL == self) {
        LogNoResource();
        return DSTAT_SYSERR_NORESOURCE;
    }   // end if

    if (NULL == (self->rawname = strdup(headerf))
        || NULL == (self->rawvalue = strdup(headerv))) {
        LogNoResource();
        DkimSignature_free(self);
        return DSTAT_SYSERR_NORESOURCE;
    }   // end if

    DkimStatus build_stat =
        DkimTagListObject_build((DkimTagListObject *) self, self->rawvalue, STRTAIL(self->rawvalue),
                                false, false);
    if (DSTAT_OK != build_stat) {
        if (DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION == build_stat) {
            build_stat = DSTAT_PERMFAIL_SIGNATURE_SYNTAX_VIOLATION;
        }   // end if
        DkimSignature_free(self);
        return build_stat;
    }   // end if

    DkimStatus validate_stat = DkimSignature_validate(self);
    if (DSTAT_OK != validate_stat) {
        DkimSignature_free(self);
        return validate_stat;
    }   // end if

    *signature = self;
    return DSTAT_OK;
}   // end function: DkimSignature_build

/**
 * release DkimSignature object
 * @param self DkimSignature object to release
 */
void
DkimSignature_free(DkimSignature *self)
{
    if (NULL == self) {
        return;
    }   // end if

    free(self->rawname);
    free(self->rawvalue);
    free(self->selector);
    free(self->sdid);
    free(self->atps_domain);
    InetMailbox_free(self->auid);
    XBuffer_free(self->signature_value);
    XBuffer_free(self->bodyhash);
    StrArray_free(self->signed_header_fields);
    IntArray_free(self->querymethod);
    free(self);
}   // end function: DkimSignature_free

/**
 * Generates DKIM-Signature header based on parameters set to the object fields.
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 * @error DSTAT_SYSERR_IMPLERROR obvious implementation error
 */
DkimStatus
DkimSignature_buildRawHeader(DkimSignature *self, bool digestmode, bool crlf, bool prepend_space,
                             const char **rawheaderf, const char **rawheaderv)
{
    DkimStatus final_stat;
    DkimStatus encode_stat;

    PTRINIT(self->rawname);
    PTRINIT(self->rawvalue);

    // Internal buffer of FoldString is extended automatically as needed,
    // so initial buffer size need not be accurate.
    FoldString *fstr = FoldString_new(BUFSIZ);
    if (NULL == fstr) {
        LogNoResource();
        final_stat = DSTAT_SYSERR_NORESOURCE;
        goto cleanup;
    }   // end if

    // buffer is incremented by 256 bytes at the reallocation
    FoldString_setGrowth(fstr, 256);
    // try to keep less than or equal to 78 bytes per line
    FoldString_setLineLengthLimits(fstr, DKIM_SIGNATURE_HEADER_WIDTH);
    /*
     * Switch a newline character, CRLF or LF.
     * CRLF to generate the header to calculate the hash,
     * "crlf" is referred to generate the header to insert to the message.
     */
    FoldString_setFoldingCR(fstr, digestmode ? true : crlf);

    // consume spaces as long as the length of "DKIM-Signature:" [SP]
    if (prepend_space) {
        FoldString_consumeLineSpace(fstr, strlen(DKIM_SIGNHEADER ":"));
        FoldString_appendChar(fstr, false, ' ');
    } else {
        FoldString_consumeLineSpace(fstr, strlen(DKIM_SIGNHEADER ": "));
    }   // end if

    // sig-v-tag
    FoldString_appendBlock(fstr, true, "v=1;");

    // sig-a-tag
    FoldString_appendBlock(fstr, true, "a=");
    FoldString_appendBlock(fstr, true, DkimEnum_lookupKeyTypeByValue(self->keytype));
    FoldString_appendChar(fstr, false, '-');
    FoldString_appendBlock(fstr, false, DkimEnum_lookupHashAlgorithmByValue(self->hashalg));
    FoldString_appendChar(fstr, true, ';');

    // sig-c-tag
    FoldString_appendBlock(fstr, true, "c=");
    FoldString_appendBlock(fstr, true, DkimEnum_lookupC14nAlgorithmByValue(self->headercanon));
    FoldString_appendChar(fstr, false, '/');
    FoldString_appendBlock(fstr, false, DkimEnum_lookupC14nAlgorithmByValue(self->bodycanon));
    FoldString_appendChar(fstr, true, ';');

    // sig-d-tag
    FoldString_appendBlock(fstr, true, "d=");
    FoldString_appendBlock(fstr, true, self->sdid);
    FoldString_appendChar(fstr, true, ';');

    // sig-h-tag
    size_t header_num = StrArray_getCount(self->signed_header_fields);
    FoldString_appendBlock(fstr, true, "h=");
    // Loop to avoid adding extra ':' to the head of the sig-h-tag
    size_t i = 0;
    FoldString_appendBlock(fstr, true, StrArray_get(self->signed_header_fields, i));
    for (++i; i < header_num; ++i) {
        FoldString_appendChar(fstr, true, ':');
        FoldString_appendBlock(fstr, true, StrArray_get(self->signed_header_fields, i));
    }   // end if
    FoldString_appendChar(fstr, true, ';');

    // sig-i-tag
    if (NULL != self->auid) {
        // local-part of AUID must be encoded as dkim-quoted-printable.
        const char *auid_localpart = InetMailbox_getLocalPart(self->auid);
        XBuffer *quoted_localpart =
            DkimConverter_encodeLocalpartToDkimQuotedPrintable(auid_localpart,
                                                               strlen(auid_localpart),
                                                               &encode_stat);
        if (NULL == quoted_localpart) {
            final_stat = encode_stat;
            goto cleanup;
        }   // end if
        XBuffer_appendChar(quoted_localpart, '@');
        XBuffer_appendString(quoted_localpart, InetMailbox_getDomain(self->auid));
        if (0 != XBuffer_status(quoted_localpart)) {
            LogNoResource();
            XBuffer_free(quoted_localpart);
            final_stat = DSTAT_SYSERR_NORESOURCE;
            goto cleanup;
        }   // end if

        FoldString_appendBlock(fstr, true, "i=");
        FoldString_appendBlock(fstr, true, XBuffer_getString(quoted_localpart));
        FoldString_appendChar(fstr, true, ';');

        XBuffer_free(quoted_localpart);
    }   // end if

    // sig-q-tag
    size_t querymethod_num = IntArray_getCount(self->querymethod);
    if (0 < querymethod_num) {
        for (i = 0; i < querymethod_num; ++i) {
            if (0 == i) {
                FoldString_appendBlock(fstr, true, "q=");
            } else {
                FoldString_appendChar(fstr, true, ':');
            }   // end if
            DkimQueryMethod querymethod = (DkimQueryMethod) IntArray_get(self->querymethod, i);
            const char *querymethod_string = DkimEnum_lookupQueryMethodByValue(querymethod);
            FoldString_appendBlock(fstr, true, querymethod_string);
        }   // end if
        FoldString_appendChar(fstr, true, ';');
    }   // end if

    // sig-s-tag
    FoldString_appendBlock(fstr, true, "s=");
    FoldString_appendBlock(fstr, true, self->selector);
    FoldString_appendChar(fstr, true, ';');

    // sig-t-tag
    FoldString_appendBlock(fstr, true, "t=");
    FoldString_appendFormatBlock(fstr, true, "%lld;", self->signing_timestamp);

    // sig-x-tag
    if (0 <= self->expiration_date) {
        FoldString_appendBlock(fstr, true, "x=");
        FoldString_appendFormatBlock(fstr, true, "%lld;", self->expiration_date);
    }   // end if

    // DKIM-ATPS
    if (DKIM_HASH_ALGORITHM_NULL != self->atps_hashalg && NULL != self->atps_domain) {
        // dkim-atps-tag
        FoldString_appendBlock(fstr, true, "atps=");
        FoldString_appendBlock(fstr, true, self->atps_domain);
        FoldString_appendChar(fstr, true, ';');

        // dkim-atpsh-tag
        const char *hashalg_string = DkimEnum_lookupAtpsHashAlgorithmByValue(self->atps_hashalg);
        FoldString_appendBlock(fstr, true, "atpsh=");
        FoldString_appendBlock(fstr, true, hashalg_string);
        FoldString_appendChar(fstr, true, ';');
    }   // end if

    // sig-bh-tag
    const void *buf = XBuffer_getBytes(self->bodyhash);
    size_t buflen = XBuffer_getSize(self->bodyhash);

    XBuffer *xbuf = DkimConverter_encodeBase64(buf, buflen, &encode_stat);
    if (NULL == xbuf) {
        final_stat = encode_stat;
        goto cleanup;
    }   // end if
    FoldString_appendBlock(fstr, true, "bh=");
    FoldString_appendNonBlock(fstr, true, XBuffer_getString(xbuf));
    FoldString_appendChar(fstr, true, ';');
    XBuffer_free(xbuf);
    xbuf = NULL;    // mark as released

    // sig-b-tag
#define DKIM_EMPTY_B_TAG_VALUE "b=;"
    if (digestmode) {
        FoldString_appendBlock(fstr, true, DKIM_EMPTY_B_TAG_VALUE);
    } else {
        if (NULL == self->signature_value) {
            DkimLogImplError("the signature value is NULL");
            final_stat = DSTAT_SYSERR_IMPLERROR;
            goto cleanup;
        }   // end if
        buf = XBuffer_getBytes(self->signature_value);
        buflen = XBuffer_getSize(self->signature_value);
        xbuf = DkimConverter_encodeBase64(buf, buflen, &encode_stat);
        if (NULL == xbuf) {
            final_stat = encode_stat;
            goto cleanup;
        }   // end if

        // It's necessary to insert line feeds symmetrically to when "digestmode" is true.
        FoldString_precede(fstr, strlen(DKIM_EMPTY_B_TAG_VALUE));

        FoldString_appendBlock(fstr, false, "b=");
        FoldString_appendNonBlock(fstr, false, XBuffer_getString(xbuf));
        FoldString_appendChar(fstr, false, ';');
        XBuffer_free(xbuf);
        xbuf = NULL;    // mark as released
    }   // end if

    // check if an error occurred on FoldString operations
    if (0 != FoldString_status(fstr)) {
        LogNoResource();
        final_stat = DSTAT_SYSERR_NORESOURCE;
        goto cleanup;
    }   // end if

    // store the generated header field
    self->rawname = strdup(DKIM_SIGNHEADER);
    if (NULL == self->rawname) {
        LogNoResource();
        final_stat = DSTAT_SYSERR_NORESOURCE;
        goto cleanup;
    }   // end if
    self->rawvalue = strdup(FoldString_getString(fstr));
    if (NULL == self->rawvalue) {
        LogNoResource();
        final_stat = DSTAT_SYSERR_NORESOURCE;
        goto cleanup;
    }
    FoldString_free(fstr);

    SETDEREF(rawheaderf, self->rawname);
    SETDEREF(rawheaderv, self->rawvalue);

    return DSTAT_OK;

  cleanup:
    FoldString_free(fstr);
    SETDEREF(rawheaderf, NULL);
    SETDEREF(rawheaderv, NULL);
    return final_stat;
}   // end function: DkimSignature_buildRawHeader

/**
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 */
DkimStatus
DkimSignature_addSignedHeaderField(DkimSignature *self, const char *headerf)
{
    if (0 > StrArray_append(self->signed_header_fields, headerf)) {
        LogNoResource();
        return DSTAT_SYSERR_NORESOURCE;
    }   // end if
    return DSTAT_OK;
}   // end function: DkimSignature_addSignedHeaderField

/**
 * Returns whether or not header field specified by "headerf" is included
 * in the list of signed header fields (sig-h-tag).
 * @return true if "headerf" is included in the list of signed header fields, false otherwise.
 */
bool
DkimSignature_isHeaderSigned(const DkimSignature *self, const char *headerf)
{
    assert(NULL != self);
    return 0 <= StrArray_linearSearchIgnoreCase(self->signed_header_fields, headerf);
}   // end function: DkimSignature_isHeaderSigned

////////////////////////////////////////////////////////////////////////
// accessor

const char *
DkimSignature_getSdid(const DkimSignature *self)
{
    return self->sdid;
}   // end function: DkimSignature_getSdid

/**
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 */
DkimStatus
DkimSignature_setSdid(DkimSignature *self, const char *domain)
{
    PTRINIT(self->sdid);
    if (NULL != domain) {
        self->sdid = strdup(domain);
        if (NULL == self->sdid) {
            LogNoResource();
            return DSTAT_SYSERR_NORESOURCE;
        }   // end if
    }   // end if
    return DSTAT_OK;
}   // end function: DkimSignature_setSdid

const char *
DkimSignature_getSelector(const DkimSignature *self)
{
    return self->selector;
}   // end function: DkimSignature_getSelector

/**
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 */
DkimStatus
DkimSignature_setSelector(DkimSignature *self, const char *selector)
{
    PTRINIT(self->selector);
    if (NULL != selector) {
        self->selector = strdup(selector);
        if (NULL == self->selector) {
            LogNoResource();
            return DSTAT_SYSERR_NORESOURCE;
        }   // end if
    }   // end if
    return DSTAT_OK;
}   // end function: DkimSignature_setSelector

DkimHashAlgorithm
DkimSignature_getHashAlgorithm(const DkimSignature *self)
{
    return self->hashalg;
}   // end function: DkimSignature_getHashAlgorithm

void
DkimSignature_setHashAlgorithm(DkimSignature *self, DkimHashAlgorithm hashalg)
{
    self->hashalg = hashalg;
}   // end function: DkimSignature_setHashAlgorithm

DkimKeyType
DkimSignature_getKeyType(const DkimSignature *self)
{
    return self->keytype;
}   // end function: DkimSignature_getKeyType

void
DkimSignature_setKeyType(DkimSignature *self, DkimKeyType keytype)
{
    self->keytype = keytype;
}   // end function: DkimSignature_setKeyType

long long
DkimSignature_getTimestamp(const DkimSignature *self)
{
    return self->signing_timestamp;
}   // end function: DkimSignature_getTimestamp

void
DkimSignature_setTimestamp(DkimSignature *self, long long timestamp)
{
    self->signing_timestamp = timestamp;
}   // end function: DkimSignature_setTimestamp

long long
DkimSignature_getExpirationDate(const DkimSignature *self)
{
    return self->expiration_date;
}   // end function: DkimSignature_getExpirationDate

void
DkimSignature_setExpirationDate(DkimSignature *self, long long expiration_date)
{
    self->expiration_date = expiration_date;
}   // end function: DkimSignature_setExpirationDate

/**
 * @attention timestamp must be set before calling this function
 *            or use DkimSignature_setExpirationDate() instead.
 */
long long
DkimSignature_setTTL(DkimSignature *self, long long ttl)
{
    if (0LL < self->signing_timestamp && 0LL < ttl) {
        self->expiration_date = self->signing_timestamp + ttl;
    } else {
        self->expiration_date = -1LL;
    }   // end if
    return self->expiration_date;
}   // end function: DkimSignature_setTTL

const XBuffer *
DkimSignature_getSignatureValue(const DkimSignature *self)
{
    return self->signature_value;
}   // end function: DkimSignature_getSignatureValue

/**
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 */
DkimStatus
DkimSignature_setSignatureValue(DkimSignature *self, unsigned char *hashbuf, unsigned int hashlen)
{
    if (NULL == self->signature_value) {
        self->signature_value = XBuffer_new(hashlen);
        if (NULL == self->signature_value) {
            LogNoResource();
            return DSTAT_SYSERR_NORESOURCE;
        }   // end if
    } else {
        XBuffer_reset(self->signature_value);
    }   // end if

    if (0 > XBuffer_appendBytes(self->signature_value, hashbuf, hashlen)) {
        LogNoResource();
        return DSTAT_SYSERR_NORESOURCE;
    }   // end if
    return DSTAT_OK;
}   // end function: DkimSignature_setSignatureValue

const XBuffer *
DkimSignature_getBodyHash(const DkimSignature *self)
{
    return self->bodyhash;
}   // end function: DkimSignature_getBodyHash

/**
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 */
DkimStatus
DkimSignature_setBodyHash(DkimSignature *self, unsigned char *hashbuf, unsigned int hashlen)
{
    if (NULL == self->bodyhash) {
        self->bodyhash = XBuffer_new(hashlen);
        if (NULL == self->bodyhash) {
            LogNoResource();
            return DSTAT_SYSERR_NORESOURCE;
        }   // end if
    } else {
        XBuffer_reset(self->bodyhash);
    }   // end if

    if (0 > XBuffer_appendBytes(self->bodyhash, hashbuf, hashlen)) {
        LogNoResource();
        return DSTAT_SYSERR_NORESOURCE;
    }   // end if
    return DSTAT_OK;
}   // end function: DkimSignature_setBodyHash

const StrArray *
DkimSignature_getSignedHeaderFields(const DkimSignature *self)
{
    return self->signed_header_fields;
}   // end function: DkimSignature_getSignedHeaderFields

/**
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 */
DkimStatus
DkimSignature_setSignedHeaderFields(DkimSignature *self, const StrArray *signed_header_fields)
{
    StrArray *copied = StrArray_copyDeeply(signed_header_fields);
    if (NULL == copied) {
        return DSTAT_SYSERR_NORESOURCE;
    }   // end if
    StrArray_free(self->signed_header_fields);
    self->signed_header_fields = copied;
    return DSTAT_OK;
}   // end function: DkimSignature_setSignedHeaderFields

DkimC14nAlgorithm
DkimSignature_getHeaderC14nAlgorithm(const DkimSignature *self)
{
    return self->headercanon;
}   // end function: DkimSignature_getHeaderC14nAlgorithm

void
DkimSignature_setHeaderC14nAlgorithm(DkimSignature *self, DkimC14nAlgorithm headercanon)
{
    self->headercanon = headercanon;
}   // end function: DkimSignature_setHeaderC14nAlgorithm

DkimC14nAlgorithm
DkimSignature_getBodyC14nAlgorithm(const DkimSignature *self)
{
    return self->bodycanon;
}   // end function: DkimSignature_getBodyC14nAlgorithm

void
DkimSignature_setBodyC14nAlgorithm(DkimSignature *self, DkimC14nAlgorithm bodycanon)
{
    self->bodycanon = bodycanon;
}   // end function: DkimSignature_setBodyC14nAlgorithm

long long
DkimSignature_getBodyLengthLimit(const DkimSignature *self)
{
    return self->body_length_limit;
}   // end function: DkimSignature_getBodyLengthLimit

void
DkimSignature_setBodyLengthLimit(DkimSignature *self, long long body_length_limit)
{
    self->body_length_limit = body_length_limit;
}   // end function: DkimSignature_setBodyLengthLimit

const char *
DkimSignature_getRawHeaderName(const DkimSignature *self)
{
    return self->rawname;
}   // end function: DkimSignature_getRawHeaderName

const char *
DkimSignature_getRawHeaderValue(const DkimSignature *self)
{
    return self->rawvalue;
}   // end function: DkimSignature_getRawHeaderValue

void
DkimSignature_getReferenceToBodyHashOfRawHeaderValue(const DkimSignature *self, const char **head,
                                                     const char **tail)
{
    *head = self->raw_value_b_head;
    *tail = self->raw_value_b_tail;
}   // end function: DkimSignature_getReferenceToBodyHashOfRawHeaderValue

const InetMailbox *
DkimSignature_getAuid(const DkimSignature *self)
{
    return self->auid;
}   // end function: DkimSignature_getAuid

/**
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 */
DkimStatus
DkimSignature_setAuid(DkimSignature *self, const InetMailbox *mailbox)
{
    InetMailbox *new_mailbox = InetMailbox_duplicate(mailbox);
    if (NULL == new_mailbox) {
        LogNoResource();
        return DSTAT_SYSERR_NORESOURCE;
    }   // end if
    InetMailbox_free(self->auid);
    self->auid = new_mailbox;
    return DSTAT_OK;
}   // end function: DkimSignature_setAuid

const IntArray *
DkimSignature_getQueryMethod(const DkimSignature *self)
{
    return self->querymethod;
}   // end function: DkimSignature_getQueryMethod

const char *
DkimSignature_getAtpsDomain(const DkimSignature *self)
{
    return self->atps_domain;
}   // end function: DkimSignature_getAtpsDomain

/**
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 */
DkimStatus
DkimSignature_setAtpsDomain(DkimSignature *self, const char *atps_domain)
{
    PTRINIT(self->atps_domain);
    if (NULL != atps_domain) {
        self->atps_domain = strdup(atps_domain);
        if (NULL == self->atps_domain) {
            LogNoResource();
            return DSTAT_SYSERR_NORESOURCE;
        }   // end if
    }   // end if
    return DSTAT_OK;
}   // end function: DkimSignature_setAtpsDomain

DkimHashAlgorithm
DkimSignature_getAtpsHashAlgorithm(const DkimSignature *self)
{
    return self->atps_hashalg;
}   // end function: DkimSignature_getAtpsHashAlgorithm

void
DkimSignature_setAtpsHashAlgorithm(DkimSignature *self, DkimHashAlgorithm atps_hashalg)
{
    self->atps_hashalg = atps_hashalg;
}   // end function: DkimSignature_setAtpsHashAlgorithm
