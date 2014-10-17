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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "loghandler.h"
#include "dkimlogger.h"
#include "stdaux.h"
#include "ptrop.h"
#include "xbuffer.h"
#include "xskip.h"
#include "xparse.h"
#include "pstring.h"
#include "intarray.h"
#include "inetdomain.h"
#include "inetmailbox.h"
#include "dnsresolv.h"
#include "dkim.h"
#include "dkimspec.h"
#include "dkimwildcard.h"
#include "dkimtaglistobject.h"
#include "dkimconverter.h"
#include "dkimsignature.h"
#include "dmarc.h"
#include "dmarcspec.h"
#include "dmarcenum.h"
#include "dmarcrecord.h"

// a limit number of records to try to check where it is valid as DMARC policy record
#define DMARC_POLICY_CANDIDATE_MAX   10

struct DmarcRecord {
    DkimTagListObject_MEMBER;
    DmarcAlignmentMode dkim_alignment;  // dmarc-adkim
    DmarcAlignmentMode spf_alignment;   // dmarc-aspf
    DmarcReportingOption failure_report_option; // (undocumented?)
    DmarcReceiverPolicy receiver_policy;    // dmarc-request
    DmarcReceiverPolicy subdomain_policy;   // dmarc-srequest
    DmarcReportFormat failure_report_format;    // dmarc-rfmt
    uint32_t aggregate_report_interval; // dmarc-ainterval
    uint8_t sampling_rate;         // dmarc-percent
    char domain[];
};

static DkimStatus DmarcRecord_parse_v(DkimTagListObject *base, const DkimTagParseContext *context,
                                      const char **nextp);
static DkimStatus DmarcRecord_parse_adkim(DkimTagListObject *base,
                                          const DkimTagParseContext *context, const char **nextp);
static DkimStatus DmarcRecord_parse_aspf(DkimTagListObject *base,
                                         const DkimTagParseContext *context, const char **nextp);
static DkimStatus DmarcRecord_parse_fo(DkimTagListObject *base, const DkimTagParseContext *context,
                                       const char **nextp);
static DkimStatus DmarcRecord_parse_p(DkimTagListObject *base, const DkimTagParseContext *context,
                                      const char **nextp);
static DkimStatus DmarcRecord_parse_pct(DkimTagListObject *base, const DkimTagParseContext *context,
                                        const char **nextp);
static DkimStatus DmarcRecord_parse_rf(DkimTagListObject *base, const DkimTagParseContext *context,
                                       const char **nextp);
static DkimStatus DmarcRecord_parse_ri(DkimTagListObject *base, const DkimTagParseContext *context,
                                       const char **nextp);
//static DkimStatus DmarcRecord_parse_rua(DkimTagListObject *base, const DkimTagParseContext *context, const char **nextp);
//static DkimStatus DmarcRecord_parse_ruf(DkimTagListObject *base, const DkimTagParseContext *context, const char **nextp);
static DkimStatus DmarcRecord_parse_sp(DkimTagListObject *base, const DkimTagParseContext *context,
                                       const char **nextp);

// parsing function table of DmarcRecord object
static const DkimTagListObjectFieldMap dmarc_record_field_table[] = {
    {"v", DmarcRecord_parse_v, true, DMARC1_VERSION_TAG},
    {"adkim", DmarcRecord_parse_adkim, false, "r"},
    {"aspf", DmarcRecord_parse_aspf, false, "r"},
    {"fo", DmarcRecord_parse_fo, false, "0"},
    {"p", DmarcRecord_parse_p, true, "none"},
    {"pct", DmarcRecord_parse_pct, false, "100"},
    {"rf", DmarcRecord_parse_rf, false, "afrf"},
    {"ri", DmarcRecord_parse_ri, false, "86400"},
    {"rua", NULL, false, NULL},
    {"ruf", NULL, false, NULL},
    {"sp", DmarcRecord_parse_sp, false, NULL},
    {NULL, NULL, false, NULL},  // sentinel
};

////////////////////////////////////////////////////////////////////////
// private functions

/*
 * [draft-kucherawy-dmarc-base-04] 5.3.
 * dmarc-version   = %x76 *WSP "=" %x44 %x4d %x41 %x52 %x43 %x31
 */
DkimStatus
DmarcRecord_parse_v(DkimTagListObject *base __attribute__((unused)),
                    const DkimTagParseContext *context, const char **nextp)
{
    /*
     * appearance at the head of record (0 == context->tag_no)
     * or set as default value (DKIM_TAGLISTOBJECT_TAG_NO_DEFAULT_VALUE == context->tag_no) are accepted.
     * error otherwise.
     * [draft-kucherawy-dmarc-base-04] 5.2.
     * It MUST be the first tag in the list.
     */
    if (DKIM_TAGLISTOBJECT_TAG_NO_AS_DEFAULT_VALUE != context->tag_no && 0 < context->tag_no) {
        SETDEREF(nextp, context->value_head);
        DkimLogPermFail
            ("dmarc-version is not appeared at the front of public key record: near %.50s",
             context->value_head);
        return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
    }   // end if

    // compare "DMARC1" tag case-sensitively
    // [draft-kucherawy-dmarc-base-04] 5.2.
    // The value of this tag MUST match precisely
    if (0 < XSkip_string(context->value_head, context->value_tail, DMARC1_VERSION_TAG, nextp)) {
        return DSTAT_OK;
    } else {
        SETDEREF(nextp, context->value_head);
        DkimLogPermFail("unsupported record version tag: near %.50s", context->value_head);
        return DSTAT_PERMFAIL_INCOMPATIBLE_RECORD_VERSION;
    }   // end if
}   // end function: DmarcRecord_parse_v

/*
 * [draft-kucherawy-dmarc-base-04] 5.3.
 * dmarc-adkim     = %x61 %x64 %x6b %x69 %x6d *WSP "=" *WSP
 *                   ( "r" / "s" )
 */
DkimStatus
DmarcRecord_parse_adkim(DkimTagListObject *base, const DkimTagParseContext *context,
                        const char **nextp)
{
    const char *p = context->value_head;
    DmarcRecord *self = (DmarcRecord *) base;

    self->dkim_alignment = DMARC_ALIGN_MODE_NULL;
    SETDEREF(nextp, context->value_head);
    if (context->value_tail <= p || !IS_ALPHA(*p)) {
        // value of dmarc-adkim does not match ALPHA
        DkimLogPermFail("dmarc-adkim does not match an alphabetic character: near %.50s",
                        context->value_head);
        return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
    }   // end if

    DmarcAlignmentMode adkim_mode = DmarcEnum_lookupAlignmentModeByNameSlice(p, p + 1);
    if (DMARC_ALIGN_MODE_NULL == adkim_mode) {
        DkimLogPermFail("dmarc-adkim does not match an valid alignment mode: near %.50s",
                        context->value_head);
        return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
    }   // end if
    self->dkim_alignment = adkim_mode;

    SETDEREF(nextp, p + 1);
    return DSTAT_OK;
}   // end function: DmarcRecord_parse_adkim

/*
 * [draft-kucherawy-dmarc-base-04] 5.3.
 * dmarc-aspf      = %x61 %x73 %x70 %x66 *WSP "=" *WSP
 *                   ( "r" / "s" )
 */
DkimStatus
DmarcRecord_parse_aspf(DkimTagListObject *base, const DkimTagParseContext *context,
                       const char **nextp)
{
    const char *p = context->value_head;
    DmarcRecord *self = (DmarcRecord *) base;

    self->spf_alignment = DMARC_ALIGN_MODE_NULL;
    SETDEREF(nextp, context->value_head);
    if (context->value_tail <= p || !IS_ALPHA(*p)) {
        // value of dmarc-aspf does not match ALPHA
        DkimLogPermFail("dmarc-aspf does not match an alphabetic character: near %.50s",
                        context->value_head);
        return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
    }   // end if

    DmarcAlignmentMode aspf_mode = DmarcEnum_lookupAlignmentModeByNameSlice(p, p + 1);
    if (DMARC_ALIGN_MODE_NULL == aspf_mode) {
        DkimLogPermFail("dmarc-aspf does not match an valid alignment mode: near %.50s",
                        context->value_head);
        return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
    }   // end if
    self->spf_alignment = aspf_mode;

    SETDEREF(nextp, p + 1);
    return DSTAT_OK;
}   // end function: DmarcRecord_parse_aspf

/*
 * [draft-kucherawy-dmarc-base-04] 5.3.
 * dmarc-fo        = %x66 %x6f *WSP "=" *WSP
 *                   ( "0" / "1" / "d" / "s" )
 *                   *(*WSP ":" *WSP ( "0" / "1" / "d" / "s" ))
 */
DkimStatus
DmarcRecord_parse_fo(DkimTagListObject *base, const DkimTagParseContext *context,
                     const char **nextp)
{
    const char *p = context->value_head;
    DmarcRecord *self = (DmarcRecord *) base;

    self->failure_report_option = DMARC_REPORT_OPTION_NULL;
    *nextp = context->value_head;
    do {
        (void) XSkip_wspBlock(p, context->value_tail, &p);
        if (context->value_tail <= p) {
            DkimLogPermFail
                ("ill-formated failure reporting option (dmarc-fo) is found in the dmarc policy record: near %.50s",
                 context->value_head);
            return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
        }   // end if

        // SPEC: take no notice of multiple times occurrence of same keyword of dmarc-fo
        DmarcReportingOption report_option = DmarcEnum_lookupReportingOptionByNameSlice(p, p + 1);
        if (DMARC_REPORT_OPTION_NULL == report_option) {
            DkimLogPermFail
                ("invalid failure reporting option (dmarc-fo) is found in the dmarc policy record: near %.50s",
                 context->value_head);
            return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
        }   // end if
        self->failure_report_option |= report_option;
        ++p;
        *nextp = p; // dmarc-fo ends at this timing if no more ':' is left

        (void) XSkip_wspBlock(p, context->value_tail, &p);
    } while (0 < XSkip_char(p, context->value_tail, ':', &p));
    return DSTAT_OK;
}   // end function: DmarcRecord_parse_fo

/*
 * [draft-kucherawy-dmarc-base-04] 5.3.
 * dmarc-request   = %x70 *WSP "=" *WSP
 *                   ( "none" / "quarantine" / "reject" )
 */
DkimStatus
DmarcRecord_parse_p(DkimTagListObject *base, const DkimTagParseContext *context, const char **nextp)
{
    const char *p = context->value_head;
    DmarcRecord *self = (DmarcRecord *) base;

    self->receiver_policy = DMARC_RECEIVER_POLICY_NULL;
    SETDEREF(nextp, context->value_head);
    const char *policy_tail = NULL;
    if (0 >= XSkip_alnumBlock(p, context->value_tail, &policy_tail)) {
        // value of dmarc-request does not match sequence of ALNUM
        goto invalid_syntax;
    }   // end if

    DmarcReceiverPolicy receiver_policy = DmarcEnum_lookupReceiverPolicyByNameSlice(p, policy_tail);
    if (DMARC_RECEIVER_POLICY_NULL == receiver_policy) {
        goto invalid_syntax;
    }   // end if
    self->receiver_policy = receiver_policy;

    SETDEREF(nextp, policy_tail);
    return DSTAT_OK;

  invalid_syntax:
    /*
     * [draft-kucherawy-dmarc-base-04] 8.
     * 6.  If a retrieved policy record does not contain a valid "p" tag, or
     *     contains an "sp" tag that is not valid, then:
     *
     *     1.  if an "rua" tag is present and contains at least one
     *         syntactically valid reporting URI, the Mail Receiver SHOULD
     *         act as if a record containing a valid "v" tag and "p=none"
     *         was retrieved, and continue processing;
     */
    self->receiver_policy = DMARC_RECEIVER_POLICY_NONE;
    SETDEREF(nextp, context->value_tail);
    return DSTAT_OK;
}   // end function: DmarcRecord_parse_p

/*
 * [draft-kucherawy-dmarc-base-04] 5.3.
 * dmarc-srequest  = %x73 %x70 *WSP "=" *WSP
 *                   ( "none" / "quarantine" / "reject" )
 */
DkimStatus
DmarcRecord_parse_sp(DkimTagListObject *base, const DkimTagParseContext *context,
                     const char **nextp)
{
    const char *p = context->value_head;
    DmarcRecord *self = (DmarcRecord *) base;

    self->subdomain_policy = DMARC_RECEIVER_POLICY_NULL;
    SETDEREF(nextp, context->value_head);
    const char *policy_tail = NULL;
    if (0 >= XSkip_alnumBlock(p, context->value_tail, &policy_tail)) {
        // value of dmarc-srequest does not match sequence of ALNUM
        DkimLogPermFail("dmarc-srequest does not match alphabetic/numeric characters: near %.50s",
                        context->value_head);
        return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
    }   // end if

    DmarcReceiverPolicy recv_policy = DmarcEnum_lookupReceiverPolicyByNameSlice(p, policy_tail);
    if (DMARC_RECEIVER_POLICY_NULL == recv_policy) {
        DkimLogPermFail("dmarc-srequest has no valid receiver policy: near %.50s",
                        context->value_head);
        return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
    }   // end if
    self->subdomain_policy = recv_policy;

    SETDEREF(nextp, policy_tail);
    return DSTAT_OK;
}   // end function: DmarcRecord_parse_sp

/*
 * [draft-kucherawy-dmarc-base-04] 5.3.
 * dmarc-ainterval = %x72 %x69 *WSP "=" *WSP 1*DIGIT
 */
DkimStatus
DmarcRecord_parse_ri(DkimTagListObject *base, const DkimTagParseContext *context,
                     const char **nextp)
{
    DmarcRecord *self = (DmarcRecord *) base;
    long long report_interval =
        DkimConverter_longlong(context->value_head, context->value_tail, DMARC_REC_RI_TAG_LEN,
                               nextp);
    if (0 <= report_interval && context->value_tail == *nextp) {
        self->aggregate_report_interval = (uint32_t) report_interval;
        return DSTAT_OK;
    } else {
        DkimLogPermFail("dmarc-ainterval has invalid value: near %.50s", context->value_head);
        return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
    }   // end if
}   // end function: DmarcRecord_parse_ri

/*
 * [draft-kucherawy-dmarc-base-04] 5.3.
 * dmarc-percent   = %x70 %x63 %x74 *WSP "=" *WSP
 *                    1*3DIGIT
 */
DkimStatus
DmarcRecord_parse_pct(DkimTagListObject *base, const DkimTagParseContext *context,
                      const char **nextp)
{
    DmarcRecord *self = (DmarcRecord *) base;
    long long report_ratio =
        DkimConverter_longlong(context->value_head, context->value_tail, DMARC_REC_PCT_TAG_LEN,
                               nextp);
    if (0 <= report_ratio && report_ratio <= 100 && context->value_tail == *nextp) {
        self->sampling_rate = (uint8_t) report_ratio;
        return DSTAT_OK;
    } else {
        DkimLogPermFail("dmarc-percent has invalid value: near %.50s", context->value_head);
        return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
    }   // end if
}   // end function: DmarcRecord_parse_pct

/*
 * [draft-kucherawy-dmarc-base-04] 5.3.
 * dmarc-rfmt      = %x72 %x66  *WSP "=" *WSP
 *                   ( "afrf" / "iodef" )
 */
DkimStatus
DmarcRecord_parse_rf(DkimTagListObject *base, const DkimTagParseContext *context,
                     const char **nextp)
{
    const char *p = context->value_head;
    DmarcRecord *self = (DmarcRecord *) base;

    self->failure_report_format = DMARC_REPORT_FORMAT_NULL;;
    SETDEREF(nextp, context->value_head);
    const char *format_tail = NULL;
    if (0 >= XSkip_alnumBlock(p, context->value_tail, &format_tail)) {
        // value of dmarc-request does not match sequence of ALNUM
        DkimLogPermFail("dmarc-rfmt does not match alphabetic/numeric characters: near %.50s",
                        context->value_head);
        return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
    }   // end if

    DmarcReportFormat rfmt = DmarcEnum_lookupReportFormatByNameSlice(p, format_tail);
    if (DMARC_REPORT_FORMAT_NULL == rfmt) {
        DkimLogPermFail("dmarc-rfmt has no valid failure report format: near %.50s",
                        context->value_head);
        return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
    }   // end if
    self->failure_report_format = rfmt;

    SETDEREF(nextp, format_tail);
    return DSTAT_OK;
}   // end function: DmarcRecord_parse_rf

////////////////////////////////////////////////////////////////////////
// public functions

/**
 * build DmarcRecord object from string
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_INFO_DNSRR_NOT_EXIST
 * @error DSTAT_PERMFAIL_INCOMPATIBLE_RECORD_VERSION
 * @error DSTAT_PERMFAIL_MULTIPLE_DNSRR
 * @error DSTAT_PERMFAIL_MISSING_REQUIRED_TAG missing required tag
 * @error DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION tag-value syntax violation
 * @error DSTAT_PERMFAIL_TAG_DUPLICATED multiple identical tags are found
 * @error DSTAT_SYSERR_IMPLERROR obvious implementation error
 */
DkimStatus
DmarcRecord_build(const char *domain, const char *keyval, DmarcRecord **dmarc_record)
{
    size_t domainlen = strlen(domain) + 1;  // includes NULL-terminator
    DmarcRecord *self = (DmarcRecord *) malloc(sizeof(DmarcRecord) + domainlen);
    if (NULL == self) {
        LogNoResource();
        return DSTAT_SYSERR_NORESOURCE;
    }   // end if
    memset(self, 0, sizeof(DmarcRecord));
    self->ftbl = dmarc_record_field_table;

    /*
     * [draft-kucherawy-dmarc-base-04] 5.2.
     * Syntax errors in the remainder of the record SHOULD be discarded in favour of
     * default values (if any) or ignored outright.
     */
    DkimStatus build_stat =
        DkimTagListObject_build((DkimTagListObject *) self, keyval, STRTAIL(keyval), true, true);
    if (DSTAT_OK != build_stat) {
        DmarcRecord_free(self);
        return build_stat;
    }   // end if

    memcpy(self->domain, domain, domainlen);
    *dmarc_record = self;
    return DSTAT_OK;
}   // end function: DmarcRecord_build

/**
 * release DmarcRecord object
 * @param self DmarcRecord object to release
 */
void
DmarcRecord_free(DmarcRecord *self)
{
    free(self);
}   // end function: DmarcRecord_free

/**
 * @error DSTAT_INFO_DNSRR_NOT_EXIST
 * @error DSTAT_PERMFAIL_MULTIPLE_DNSRR
 */
static DkimStatus
DmarcRecord_checkVersionTag(const DnsTxtResponse *txt_rr, size_t *index)
{
    /*
     * [draft-kucherawy-dmarc-base-04] 8.
     * 2.  Records that do not start with a "v=" tag that identifies the
     *    current version of DMARC are discarded.
     * (ditto with 4.)
     * [draft-kucherawy-dmarc-base-04] 5.2.
     * v: Version (plain-text; REQUIRED).  Identifies the record retrieved
     *   as a DMARC record.  It MUST have the value of "DMARC1".  The value
     *   of this tag MUST match precisely; if it does not or it is absent,
     *   the entire retrieved record MUST be ignored.  It MUST be the first
     *   tag in the list.
     */
    int valid_index = -1;
    for (size_t txtrr_idx = 0; txtrr_idx < txt_rr->num; ++txtrr_idx) {
        const char *txtrecord = txt_rr->data[0];
        if (0 == strncmp(txtrecord, DMARC1_RECORD_PREFIX, strlen(DMARC1_RECORD_PREFIX))) {
            if (0 <= valid_index) {
                return DSTAT_PERMFAIL_MULTIPLE_DNSRR;
            }   // end if
            valid_index = (int) txtrr_idx;
        }   // end if
    }   // end for

    if (0 <= valid_index) {
        SETDEREF(index, (size_t) valid_index);
        return DSTAT_OK;
    } else {
        return DSTAT_INFO_DNSRR_NOT_EXIST;
    }   // end if
}   // end function: DmarcRecord_checkVersionTag

/**
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_INFO_DNSRR_NOT_EXIST DMARC record does not exist
 * @error DSTAT_TMPERR_DNS_ERROR_RESPONSE DNS lookup error (received error response)
 * @error DSTAT_PERMFAIL_INCOMPATIBLE_RECORD_VERSION
 * @error DSTAT_PERMFAIL_MULTIPLE_DNSRR
 * @error DSTAT_PERMFAIL_MISSING_REQUIRED_TAG missing required tag
 * @error DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION tag-value syntax violation
 * @error DSTAT_PERMFAIL_TAG_DUPLICATED multiple identical tags are found
 * @error DSTAT_SYSERR_DNS_LOOKUP_FAILURE DNS lookup error (failed to lookup itself)
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 * @error DSTAT_SYSERR_IMPLERROR obvious implementation error
 */
static DkimStatus
DmarcRecord_query(const char *domain, DnsResolver *resolver, DmarcRecord **dmarc_record)
{
    assert(NULL != domain);
    assert(NULL != resolver);

    /*
     * [draft-kucherawy-dmarc-base-04] 5.
     * Domain Owner DMARC preferences are stored as DNS TXT records in
     * subdomains named "_dmarc".
     */
    size_t dmarc_domain_len = strlen(domain) + sizeof(DMARC_RECORD_DNS_PREFIX "."); // "sizeof" operator returns the size including NULL terminator
    char dmarc_domain[dmarc_domain_len];
    snprintf(dmarc_domain, dmarc_domain_len, DMARC_RECORD_DNS_PREFIX ".%s", domain);

    // lookup DMARC record
    DnsTxtResponse *txt_rr = NULL;
    dns_stat_t txtquery_stat = DnsResolver_lookupTxt(resolver, dmarc_domain, &txt_rr);
    switch (txtquery_stat) {
    case DNS_STAT_NOERROR:;
        // one or more TXT RRs are found

        size_t record_index = 0;
        DkimStatus record_stat = DmarcRecord_checkVersionTag(txt_rr, &record_index);
        if (DSTAT_OK != record_stat) {
            /*
             * [draft-kucherawy-dmarc-base-04] 8.
             * 5.  If the remaining set contains multiple records or no records,
             *     processing terminates and the Mail Receiver takes no action.
             * (snip)
             * If the set produced by the mechanism above contains no DMARC policy
             * record (i.e., any indication that there is no such record as opposed
             * to a transient DNS error), Mail Receivers SHOULD NOT apply the DMARC
             * mechanism to the message.
             */
            LogDebug("No or multiple DMARC record candidates are found: domain=%s", domain);
            DnsTxtResponse_free(txt_rr);
            return record_stat;
        }   // end if

        // Parse only remaining TXT RR as DMARC record
        const char *txtrecord = txt_rr->data[record_index];
        DmarcRecord *self = NULL;
        DkimStatus build_stat = DmarcRecord_build(domain, txtrecord, &self);
        if (DSTAT_OK == build_stat) {
            // parsed successfully as a valid DMARC record
            *dmarc_record = self;
            DnsTxtResponse_free(txt_rr);
            return DSTAT_OK;
        } else if (DSTAT_ISCRITERR(build_stat)) {
            // propagate system errors as-is
            DkimLogSysError
                ("System error has occurred while parsing DMARC record: domain=%s, error=%s, record=[%s]",
                 domain, DkimStatus_getSymbol(build_stat), NNSTR(txtrecord));
            DnsTxtResponse_free(txt_rr);
            return build_stat;
        } else if (DSTAT_ISPERMFAIL(build_stat)) {
            /*
             * [draft-kucherawy-dmarc-base-04] 16.2.
             * Code:  permerror
             * (snip)
             * Meaning:  A permanent error occurred during DMARC evaluation, such as
             *   encountering a syntactically incorrect DMARC record.  A later
             *   attempt is unlikely to produce a final result.
             */
            DkimLogPermFail("invalid DMARC record: domain=%s, error=%s, record=[%s]",
                            domain, DkimStatus_getSymbol(build_stat), NNSTR(txtrecord));
            DnsTxtResponse_free(txt_rr);
            return build_stat;
        } else {
            // must not reach here
            LogNotice("DmarcRecord_build failed: domain=%s, error=%s, record=[%s]",
                      domain, DkimStatus_getSymbol(build_stat), NNSTR(txtrecord));
            DnsTxtResponse_free(txt_rr);
            return build_stat;
        }   // end if
        // does not reach here
        break;

    case DNS_STAT_NXDOMAIN:
    case DNS_STAT_NODATA:
    case DNS_STAT_NOVALIDANSWER:
        /*
         * No TXT records are found
         *
         * [draft-kucherawy-dmarc-base-04] 8.
         * 5.  If the remaining set contains multiple records or no records,
         *     processing terminates and the Mail Receiver takes no action.
         * (snip)
         * If the set produced by the mechanism above contains no DMARC policy
         * record (i.e., any indication that there is no such record as opposed
         * to a transient DNS error), Mail Receivers SHOULD NOT apply the DMARC
         * mechanism to the message.
         */
        LogDebug("No DMARC record candidate TXT records are found: domain=%s", domain);
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
         * [draft-kucherawy-dmarc-base-04] 8.
         * Handling of DNS errors when querying for the DMARC policy record is
         * left to the discretion of the Mail Receiver.
         */
        LogDnsError("txt", domain, "DMARC record", DnsResolver_getErrorSymbol(resolver));
        return DSTAT_TMPERR_DNS_ERROR_RESPONSE;

    case DNS_STAT_SYSTEM:
        DkimLogSysError("System error occurred on DNS lookup: rrtype=txt, domain=%s, error=%s",
                        domain, DnsResolver_getErrorSymbol(resolver));
        return DSTAT_SYSERR_DNS_LOOKUP_FAILURE;

    case DNS_STAT_NOMEMORY:
        LogNoResource();
        return DSTAT_SYSERR_NORESOURCE;

    case DNS_STAT_BADREQUEST:
    default:
        DkimLogImplError
            ("DnsResolver_lookupTxt returns unexpected value: value=0x%x, rrtype=txt, domain=%s",
             txtquery_stat, domain);
        return DSTAT_SYSERR_IMPLERROR;
    }   // end switch
}   // end function: DmarcRecord_query

/**
 * Perform the DMARC Record discovery described in draft-kucherawy-dmarc-base-04 Section 8.
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_INFO_DNSRR_NOT_EXIST DMARC record does not exist
 * @error DSTAT_TMPERR_DNS_ERROR_RESPONSE DNS lookup error (received error response)
 * @error DSTAT_PERMFAIL_INCOMPATIBLE_RECORD_VERSION
 * @error DSTAT_PERMFAIL_MULTIPLE_DNSRR
 * @error DSTAT_PERMFAIL_MISSING_REQUIRED_TAG missing required tag
 * @error DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION tag-value syntax violation
 * @error DSTAT_PERMFAIL_TAG_DUPLICATED multiple identical tags are found
 * @error DSTAT_SYSERR_DNS_LOOKUP_FAILURE DNS lookup error (failed to lookup itself)
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 * @error DSTAT_SYSERR_IMPLERROR obvious implementation error
 */
DkimStatus
DmarcRecord_discover(const char *authordomain, const PublicSuffix *public_suffix,
                     DnsResolver *resolver, DmarcRecord **dmarc_record)
{
    assert(NULL != authordomain);
    assert(NULL != resolver);
    assert(NULL != dmarc_record);

    /*
     * [draft-kucherawy-dmarc-base-04] 8.
     * 1.  Mail Receivers MUST query the DNS for a DMARC TXT record at the
     *     DNS domain matching the one found in the RFC5322.From domain in
     *     the message.  A possibly empty set of records is returned.
     *
     * 2.  Records that do not start with a "v=" tag that identifies the
     *     current version of DMARC are discarded.
     */
    DkimStatus query_stat = DmarcRecord_query(authordomain, resolver, dmarc_record);
    if (DSTAT_INFO_DNSRR_NOT_EXIST == query_stat) {
        /*
         * [draft-kucherawy-dmarc-base-04] 8.
         * 3.  If the set is now empty, the Mail Receiver MUST query the DNS for
         *     a DMARC TXT record at the DNS domain matching the Organizational
         *     Domain in place of the RFC5322.From domain in the message (if
         *     different).  This record can contain policy to be asserted for
         *     subdomains of the Organizational Domain.  A possibly empty set of
         *     records is returned.
         *
         * 4.  Records that do not start with a "v=" tag that identifies the
         *     current version of DMARC are discarded.
         */
        const char *organizational_domain =
            PublicSuffix_getOrganizationalDomain(public_suffix, authordomain);
        if (NULL != organizational_domain && 0 != strcasecmp(authordomain, organizational_domain)) {
            query_stat = DmarcRecord_query(organizational_domain, resolver, dmarc_record);
        }   // end if
    }   // end if

    return query_stat;
}   // end function: DmarcRecord_discover

////////////////////////////////////////////////////////////////////////
// accessor

const char *
DmarcRecord_getDomain(const DmarcRecord *self)
{
    return self->domain;
}   // end function: DmarcRecord_getDomain

DmarcReceiverPolicy
DmarcRecord_getReceiverPolicy(const DmarcRecord *self)
{
    return self->receiver_policy;
}   // end function: DmarcRecord_getReceiverPolicy

DmarcReceiverPolicy
DmarcRecord_getSubdomainPolicy(const DmarcRecord *self)
{
    return self->subdomain_policy;
}   // end function: DmarcRecord_getSubdomainPolicy

DmarcAlignmentMode
DmarcRecord_getSpfAlignmentMode(const DmarcRecord *self)
{
    return self->spf_alignment;
}   // end function: DmarcRecord_getSpfAlignmentMode

DmarcAlignmentMode
DmarcRecord_getDkimAlignmentMode(const DmarcRecord *self)
{
    return self->dkim_alignment;
}   // end function: DmarcRecord_getDkimAlignmentMode

uint8_t
DmarcRecord_getSamplingRate(const DmarcRecord *self)
{
    return self->sampling_rate;
}   // end function: DmarcRecord_getSamplingRate
