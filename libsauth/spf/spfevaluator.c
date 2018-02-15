/*
 * Copyright (c) 2007-2014 Internet Initiative Japan Inc. All rights reserved.
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

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/socket.h>
#include <arpa/nameser.h>
#include <netinet/in.h>
#include <netdb.h>
#include <resolv.h>

#include "stdaux.h"
#include "ptrop.h"
#include "loghandler.h"
#include "spflogger.h"
#include "strarray.h"
#include "xskip.h"
#include "inetdomain.h"
#include "inetmailbox.h"
#include "bitmemcmp.h"
#include "dnsresolv.h"
#include "spf.h"
#include "spfenum.h"
#include "spfrecord.h"
#include "spfevaluator.h"
#include "spfmacro.h"

#define SPF_EVAL_DEFAULT_LOCALPART "postmaster"

typedef struct SpfRawRecord {
    const char *record_head;
    const char *record_tail;
    const char *scope_tail;
    SpfRecordScope scope;
} SpfRawRecord;

static SpfScore SpfEvaluator_checkHost(SpfEvaluator *self, const char *domain,
                                       bool count_void_lookup);

static unsigned int
SpfEvaluator_getDepth(const SpfEvaluator *self)
{
    return self->redirect_depth + self->include_depth;
}   // end function: SpfEvaluator_getDepth

static SpfStat
SpfEvaluator_pushDomain(SpfEvaluator *self, const char *domain)
{
    if (0 <= StrArray_append(self->domain, domain)) {
        return SPF_STAT_OK;
    } else {
        LogNoResource();
        return SPF_STAT_NO_RESOURCE;
    }   // end if
}   // end function: SpfEvaluator_pushDomain

static void
SpfEvaluator_popDomain(SpfEvaluator *self)
{
    StrArray_unappend(self->domain);
}   // end function: SpfEvaluator_popDomain

const char *
SpfEvaluator_getDomain(const SpfEvaluator *self)
{
    size_t n = StrArray_getCount(self->domain);
    return 0 < n ? StrArray_get(self->domain, n - 1) : NULL;
}   // end function: SpfEvaluator_getDomain

static SpfScore
SpfEvaluator_getScoreByQualifier(SpfQualifier qualifier)
{
    // SpfQualifier は各スコアに対応する値を持たせているのでキャストするだけでよい
    return (SpfScore) qualifier;
}   // end function: SpfEvaluator_getScoreByQualifier

bool
SpfEvaluator_isSenderContext(const SpfEvaluator *self)
{
    return self->is_sender_context;
}   // end function: SpfEvaluator_isSenderContext

const InetMailbox *
SpfEvaluator_getSender(const SpfEvaluator *self)
{
    return self->sender;
}   // end function: SpfEvaluator_getSender

const char *
SpfEvaluator_getEvaluatedDomain(const SpfEvaluator *self)
{
    return self->is_sender_context ? InetMailbox_getDomain(self->sender) : self->helo_domain;
}   // end function: SpfEvaluator_getEvaluatedDomain

const char *
SpfEvaluator_getExplanation(const SpfEvaluator *self)
{
    return self->explanation;
}   // end function: SpfEvaluator_getExplanation

static SpfStat
SpfEvaluator_setExplanation(SpfEvaluator *self, const char *domain, const char *exp_macro)
{
    const char *nextp;
    XBuffer_reset(self->xbuf);
    SpfStat parse_stat =
        SpfMacro_parseExplainString(self, exp_macro, STRTAIL(exp_macro), &nextp, self->xbuf);
    if (SPF_STAT_OK == parse_stat && STRTAIL(exp_macro) == nextp) {
        LogDebug("explanation record: domain=%s, exp=%s", domain, XBuffer_getString(self->xbuf));
        if (NULL != self->explanation) {
            // "exp=" の評価条件が重複している証拠なのでバグ
            SpfLogImplError("clean up existing explanation: exp=%s", self->explanation);
            free(self->explanation);
            self->explanation = NULL;
        }   // end if
        // ignoring memory allocation error
        self->explanation = XBuffer_dupString(self->xbuf);
    } else {
        LogInfo("explanation expansion failed: domain=%s, exp=%s", domain, exp_macro);
    }   // end if
    return parse_stat;
}   // end function: SpfEvaluator_setExplanation

/**
 * スコープに一致する唯一つのレコードを選択する.
 * @return スコープに一致するレコードが唯一つ見つかった場合, または見つからなかった場合は SPF_SCORE_NULL,
 *         スコープに一致するレコードが複数見つかった場合は SPF_SCORE_PERMERROR.
 */
static SpfScore
SpfEvaluator_uniqueByScope(const SpfRawRecord *rawrecords, unsigned int recordnum,
                           SpfRecordScope scope, const SpfRawRecord **selected)
{
    assert(NULL == *selected);

    for (size_t n = 0; n < recordnum; ++n) {
        if (scope & rawrecords[n].scope) {
            if (NULL == *selected) {
                *selected = &(rawrecords[n]);
            } else {
                // スコープに一致する SPF レコードが複数存在した
                return SPF_SCORE_PERMERROR;
            }   // end if
        }   // end if
    }   // end for

    return SPF_SCORE_NULL;
}   // end function: SpfEvaluator_uniqueByScope

static SpfScore
SpfEvaluator_incrementVoidLookupCounter(SpfEvaluator *self, dns_stat_t query_stat)
{
    if (DNS_STAT_NODATA == query_stat || DNS_STAT_NXDOMAIN == query_stat) {
        ++self->void_lookup_count;
        if (0 <= self->policy->void_lookup_limit
            && self->policy->void_lookup_limit < (int) self->void_lookup_count) {
            /* [RFC7208] 11.1.
             * Operational experience since the publication of
             * [RFC4408] suggests that mitigation of this class of attack can be
             * accomplished with minimal impact on the deployed base by having
             * the verifier abort processing and return "permerror"
             * (Section 2.6.7) as soon as more than two "void lookups" have been
             * encountered (defined in Section 4.6.4).
             */
            return SPF_SCORE_PERMERROR;
        }   // end if
    }   // end if
    return SPF_SCORE_NULL;
}   // end function: SpfEvaluator_incrementVoidLookupCounter

/**
 * @return 成功した場合は SPF_SCORE_NULL, SPFレコード取得の際にエラーが発生した場合は SPF_SCORE_NULL 以外.
 */
static SpfScore
SpfEvaluator_fetch(SpfEvaluator *self, const char *domain, bool count_void_lookup,
                   DnsTxtResponse **txtresp)
{
    if (self->policy->lookup_spf_rr) {
        dns_stat_t spfquery_stat = DnsResolver_lookupSpf(self->resolver, domain, txtresp);
        switch (spfquery_stat) {
        case DNS_STAT_NOERROR:
            /*
             * RFC4406, 4408 とも SPF RR が存在した場合は全ての TXT RR を破棄するので,
             * SPF RR が見つかった場合は TXT RR をルックアップせずにこのまま戻せばよい.
             * [RFC4406] 4.4.
             * 1. If any records of type SPF are in the set, then all records of
             *    type TXT are discarded.
             * [RFC4408] 4.5.
             * 2. If any records of type SPF are in the set, then all records of
             *    type TXT are discarded.
             */
            return SPF_SCORE_NULL;
        case DNS_STAT_NODATA:
        case DNS_STAT_NOVALIDANSWER:
            // SPF RR がないので TXT RR にフォールバック
            break;
        case DNS_STAT_NXDOMAIN:
            /*
             * [RFC4406] 4.3.
             * When performing the PRA version of the test, if the DNS query returns
             * "non-existent domain" (RCODE 3), then check_host() exits immediately
             * with the result "Fail".
             * [RFC4408] 4.3.
             * If the <domain> is malformed (label longer than 63 characters, zero-
             * length label not at the end, etc.) or is not a fully qualified domain
             * name, or if the DNS lookup returns "domain does not exist" (RCODE 3),
             * check_host() immediately returns the result "None".
             */
            return (self->scope & SPF_RECORD_SCOPE_SPF2_PRA)
                ? SPF_SCORE_FAIL : SPF_SCORE_NONE;
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
             * [RFC4408] 4.4.
             * If all DNS lookups that are made return a server failure (RCODE 2),
             * or other error (RCODE other than 0 or 3), or time out, then
             * check_host() exits immediately with the result "TempError".
             */
            LogDnsError("spf", domain, "SPF Record", DnsResolver_getErrorSymbol(self->resolver));
            return SPF_SCORE_TEMPERROR;
        case DNS_STAT_BADREQUEST:
        case DNS_STAT_SYSTEM:
        case DNS_STAT_NOMEMORY:
        default:
            LogDnsError("spf", domain, "SPF Record", DnsResolver_getErrorSymbol(self->resolver));
            return SPF_SCORE_SYSERROR;
        }   // end switch
    }   // end if

    // TXT RR を引く
    dns_stat_t txtquery_stat = DnsResolver_lookupTxt(self->resolver, domain, txtresp);
    switch (txtquery_stat) {
    case DNS_STAT_NOERROR:
        return SPF_SCORE_NULL;
    case DNS_STAT_NODATA:  // NOERROR
        /*
         * [RFC4406] 4.4.
         * If there are no matching records remaining after the initial DNS
         * query or any subsequent optional DNS queries, then check_host() exits
         * immediately with the result "None".
         * [RFC4408] 4.5.
         * If no matching records are returned, an SPF client MUST assume that
         * the domain makes no SPF declarations.  SPF processing MUST stop and
         * return "None".
         */
        if (count_void_lookup
            && SPF_SCORE_PERMERROR == SpfEvaluator_incrementVoidLookupCounter(self,
                                                                              txtquery_stat)) {
            LogDnsError("txt", domain, "SPF Record", "VOIDLOOKUP_EXCEEDS");
            return SPF_SCORE_PERMERROR;
        }   // end if
        // fall through

    case DNS_STAT_NOVALIDANSWER:
        return SPF_SCORE_NONE;

    case DNS_STAT_NXDOMAIN:
        /*
         * [RFC4406] 4.3.
         * When performing the PRA version of the test, if the DNS query returns
         * "non-existent domain" (RCODE 3), then check_host() exits immediately
         * with the result "Fail".
         * [RFC4408] 4.3.
         * If the <domain> is malformed (label longer than 63 characters, zero-
         * length label not at the end, etc.) or is not a fully qualified domain
         * name, or if the DNS lookup returns "domain does not exist" (RCODE 3),
         * check_host() immediately returns the result "None".
         */
        if (count_void_lookup
            && SPF_SCORE_PERMERROR == SpfEvaluator_incrementVoidLookupCounter(self,
                                                                              txtquery_stat)) {
            LogDnsError("txt", domain, "SPF Record", "VOIDLOOKUP_EXCEEDS");
            return SPF_SCORE_PERMERROR;
        }   // end if
        return (self->scope & SPF_RECORD_SCOPE_SPF2_PRA) ? SPF_SCORE_FAIL : SPF_SCORE_NONE;

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
         * [RFC4408] 4.4.
         * If all DNS lookups that are made return a server failure (RCODE 2),
         * or other error (RCODE other than 0 or 3), or time out, then
         * check_host() exits immediately with the result "TempError".
         */
        LogDnsError("txt", domain, "SPF Record", DnsResolver_getErrorSymbol(self->resolver));
        return SPF_SCORE_TEMPERROR;
    case DNS_STAT_BADREQUEST:
    case DNS_STAT_SYSTEM:
    case DNS_STAT_NOMEMORY:
    default:
        LogDnsError("txt", domain, "SPF Record", DnsResolver_getErrorSymbol(self->resolver));
        return SPF_SCORE_SYSERROR;
    }   // end switch
}   // end function: SpfEvaluator_fetch

static SpfScore
SpfEvaluator_lookupRecord(SpfEvaluator *self, const char *domain, bool count_void_lookup,
                          SpfRecord **record)
{
    DnsTxtResponse *txtresp = NULL;
    SpfScore fetch_score = SpfEvaluator_fetch(self, domain, count_void_lookup, &txtresp);
    if (SPF_SCORE_NULL != fetch_score) {
        return fetch_score;
    }   // end if
    assert(NULL != txtresp);

    // 各レコードのスコープを調べる
    SpfRawRecord rawrecords[txtresp->num];
    for (size_t n = 0; n < txtresp->num; ++n) {
        rawrecords[n].record_head = txtresp->data[n];
        rawrecords[n].record_tail = STRTAIL(txtresp->data[n]);
        (void) SpfRecord_getSpfScope(rawrecords[n].record_head, rawrecords[n].record_tail,
                                     &(rawrecords[n].scope), &(rawrecords[n].scope_tail));
    }   // end for

    // SIDF のスコープを持つ場合は SIDF レコードを探す
    const SpfRawRecord *selected = NULL;
    if (self->scope & (SPF_RECORD_SCOPE_SPF2_MFROM | SPF_RECORD_SCOPE_SPF2_PRA)) {
        SpfScore select_score =
            SpfEvaluator_uniqueByScope(rawrecords, txtresp->num, self->scope, &selected);
        if (SPF_SCORE_NULL != select_score) {
            SpfLogPermFail
                ("multiple spf2 record found: domain=%s, spf2-mfrom=%s, spf2-pra=%s",
                 domain, self->scope & SPF_RECORD_SCOPE_SPF2_MFROM ? "true" : "false",
                 self->scope & SPF_RECORD_SCOPE_SPF2_PRA ? "true" : "false");
            DnsTxtResponse_free(txtresp);
            return select_score;
        }   // end if
    }   // end if

    // SPFv1 のスコープを持つ場合, SIDF のスコープを持つが SIDF レコードが見つからなかった場合は SPF レコードを探す
    if (NULL == selected) {
        SpfScore select_score =
            SpfEvaluator_uniqueByScope(rawrecords, txtresp->num, SPF_RECORD_SCOPE_SPF1, &selected);
        if (SPF_SCORE_NULL != select_score) {
            SpfLogPermFail("multiple spf1 record found: domain=%s, spf1=%s", domain,
                           self->scope & SPF_RECORD_SCOPE_SPF1 ? "true" : "false");
            DnsTxtResponse_free(txtresp);
            return select_score;
        }   // end if
    }   // end if

    if (NULL == selected) {
        // スコープに一致する SPF/SIDF レコードが存在しなかった
        LogDebug("no spf record found: domain=%s, spf1=%s, spf2-mfrom=%s, spf2-pra=%s", domain,
                 self->scope & SPF_RECORD_SCOPE_SPF1 ? "true" : "false",
                 self->scope & SPF_RECORD_SCOPE_SPF2_MFROM ? "true" : "false",
                 self->scope & SPF_RECORD_SCOPE_SPF2_PRA ? "true" : "false");
        DnsTxtResponse_free(txtresp);
        return SPF_SCORE_NONE;
    }   // end if

    // スコープに一致する SPF/SIDF レコードが唯一つ存在した
    // レコードのパース
    SpfStat build_stat =
        SpfRecord_build(self, selected->scope, selected->scope_tail, selected->record_tail, record);
    DnsTxtResponse_free(txtresp);
    switch (build_stat) {
    case SPF_STAT_OK:
        return SPF_SCORE_NULL;
    case SPF_STAT_NO_RESOURCE:
        return SPF_SCORE_SYSERROR;
    default:
        return SPF_SCORE_PERMERROR;
    }   // end switch
}   // end function: SpfEvaluator_lookupRecord

static const char *
SpfEvaluator_getTargetName(const SpfEvaluator *self, const SpfTerm *term)
{
    return term->querydomain ? term->querydomain : SpfEvaluator_getDomain(self);
}   // end function: SpfEvaluator_getTargetName

/*
 * メカニズム評価中の DNS レスポンスエラーコードを SPF のスコアにマップする.
 */
static SpfScore
SpfEvaluator_mapMechDnsResponseToSpfScore(dns_stat_t resolv_stat)
{
    /*
     * [RFC4408 5.]
     * Several mechanisms rely on information fetched from DNS.  For these
     * DNS queries, except where noted, if the DNS server returns an error
     * (RCODE other than 0 or 3) or the query times out, the mechanism
     * throws the exception "TempError".  If the server returns "domain does
     * not exist" (RCODE 3), then evaluation of the mechanism continues as
     * if the server returned no error (RCODE 0) and zero answer records.
     */
    switch (resolv_stat) {
    case DNS_STAT_NOERROR:
    case DNS_STAT_NODATA:
    case DNS_STAT_NOVALIDANSWER:
    case DNS_STAT_NXDOMAIN:
        return SPF_SCORE_NULL;
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
        return SPF_SCORE_TEMPERROR;
    case DNS_STAT_BADREQUEST:
    case DNS_STAT_SYSTEM:
    case DNS_STAT_NOMEMORY:
    default:
        return SPF_SCORE_SYSERROR;
    }   // end switch
}   // end function: SpfEvaluator_mapMechDnsResponseToSpfScore

static SpfScore
SpfEvaluator_incrementDnsMechCounter(SpfEvaluator *self)
{
    if (++(self->dns_mech_count) <= self->policy->max_dns_mech) {
        return SPF_SCORE_NULL;
    } else {
        SpfLogPermFail("over %d mechanisms with dns look up evaluated: sender=%s, domain=%s",
                       self->policy->max_dns_mech, InetMailbox_getDomain(self->sender),
                       SpfEvaluator_getDomain(self));
        return SPF_SCORE_PERMERROR;
    }   // end if
}   // end function: SpfEvaluator_incrementDnsMechCounter

static SpfScore
SpfEvaluator_checkMaliceOfCidrLength(const SpfEvaluator *self, char ip_version,
                                     unsigned short cidr_length,
                                     unsigned char malicious_cidr_length,
                                     SpfCustomAction action_on_malicious_cidr_length)
{
    if (SPF_CUSTOM_ACTION_NULL != action_on_malicious_cidr_length
        && cidr_length <= malicious_cidr_length) {
        switch (action_on_malicious_cidr_length) {
        case SPF_CUSTOM_ACTION_NULL:
        case SPF_CUSTOM_ACTION_SCORE_NONE:
        case SPF_CUSTOM_ACTION_SCORE_NEUTRAL:
        case SPF_CUSTOM_ACTION_SCORE_PASS:
        case SPF_CUSTOM_ACTION_SCORE_POLICY:
        case SPF_CUSTOM_ACTION_SCORE_FAIL:
        case SPF_CUSTOM_ACTION_SCORE_SOFTFAIL:
        case SPF_CUSTOM_ACTION_SCORE_TEMPERROR:
        case SPF_CUSTOM_ACTION_SCORE_PERMERROR:
            return (SpfScore) action_on_malicious_cidr_length;
        case SPF_CUSTOM_ACTION_LOGGING:
            // XXX to be refined
            LogInfo
                ("Found malicious ip%c-cidr-length in SPF record: domain=%s, ip%c-cidr-length=%hu, threshold=%hhu",
                 ip_version, SpfEvaluator_getDomain(self), ip_version, malicious_cidr_length,
                 cidr_length);
            break;
        default:
            abort();
        }   // end switch
    }   // end if
    return SPF_SCORE_NULL;
}   // end function: SpfEvaluator_checkMaliceOfCidrLength

static SpfScore
SpfEvaluator_checkMaliceOfIp4CidrLength(const SpfEvaluator *self, const SpfTerm *term)
{
    return SpfEvaluator_checkMaliceOfCidrLength(self, '4', term->ip4cidr,
                                                self->policy->malicious_ip4_cidr_length,
                                                self->policy->action_on_malicious_ip4_cidr_length);
}   // end function: SpfEvaluator_checkMaliceOfIp4CidrLength

static SpfScore
SpfEvaluator_checkMaliceOfIp6CidrLength(const SpfEvaluator *self, const SpfTerm *term)
{
    return SpfEvaluator_checkMaliceOfCidrLength(self, '6', term->ip6cidr,
                                                self->policy->malicious_ip6_cidr_length,
                                                self->policy->action_on_malicious_ip6_cidr_length);
}   // end function: SpfEvaluator_checkMaliceOfIp6CidrLength

static SpfScore
SpfEvaluator_checkMaliceOfDualCidrLength(const SpfEvaluator *self, const SpfTerm *term)
{
    SpfScore score = SpfEvaluator_checkMaliceOfIp4CidrLength(self, term);
    if (SPF_SCORE_NULL != score) {
        return score;
    }   // end if
    return SpfEvaluator_checkMaliceOfIp6CidrLength(self, term);
}   // end function: SpfEvaluator_checkMaliceOfDualCidrLength

static SpfScore
SpfEvaluator_checkPlusAllDirective(const SpfEvaluator *self, const SpfTerm *term)
{
    if (SPF_CUSTOM_ACTION_NULL != self->policy->action_on_plus_all_directive
        && SPF_QUALIFIER_PLUS == term->qualifier) {
        switch (self->policy->action_on_plus_all_directive) {
        case SPF_CUSTOM_ACTION_NULL:
        case SPF_CUSTOM_ACTION_SCORE_NONE:
        case SPF_CUSTOM_ACTION_SCORE_NEUTRAL:
        case SPF_CUSTOM_ACTION_SCORE_PASS:
        case SPF_CUSTOM_ACTION_SCORE_POLICY:
        case SPF_CUSTOM_ACTION_SCORE_FAIL:
        case SPF_CUSTOM_ACTION_SCORE_SOFTFAIL:
        case SPF_CUSTOM_ACTION_SCORE_TEMPERROR:
        case SPF_CUSTOM_ACTION_SCORE_PERMERROR:
            return (SpfScore) self->policy->action_on_plus_all_directive;
        case SPF_CUSTOM_ACTION_LOGGING:
            // XXX to be refined
            LogInfo("Found +all directive in SPF record: domain=%s", SpfEvaluator_getDomain(self));
            break;
        default:
            abort();
        }   // end switch
    }   // end if
    return SPF_SCORE_NULL;
}   // end function: SpfEvaluator_checkPlusAllDirective

static SpfScore
SpfEvaluator_evalMechAll(const SpfEvaluator *self, const SpfTerm *term)
{
    SpfScore score = SpfEvaluator_checkPlusAllDirective(self, term);
    if (score != SPF_SCORE_NULL) {
        return score;
    }   // end if

    return SPF_SCORE_NULL == self->policy->overwrite_all_directive_score
        ? SpfEvaluator_getScoreByQualifier(term->qualifier)
        : self->policy->overwrite_all_directive_score;
}   // end function: SpfEvaluator_evalMechAll

static SpfScore
SpfEvaluator_evalMechInclude(SpfEvaluator *self, const SpfTerm *term)
{
    assert(SPF_TERM_PARAM_DOMAINSPEC == term->attr->param_type);
    ++(self->include_depth);
    SpfScore eval_score = SpfEvaluator_checkHost(self, term->querydomain, true);
    --(self->include_depth);
    /*
     * [RFC4408] 5.2.
     * Whether this mechanism matches, does not match, or throws an
     * exception depends on the result of the recursive evaluation of
     * check_host():
     *
     * +---------------------------------+---------------------------------+
     * | A recursive check_host() result | Causes the "include" mechanism  |
     * | of:                             | to:                             |
     * +---------------------------------+---------------------------------+
     * | Pass                            | match                           |
     * |                                 |                                 |
     * | Fail                            | not match                       |
     * |                                 |                                 |
     * | SoftFail                        | not match                       |
     * |                                 |                                 |
     * | Neutral                         | not match                       |
     * |                                 |                                 |
     * | TempError                       | throw TempError                 |
     * |                                 |                                 |
     * | PermError                       | throw PermError                 |
     * |                                 |                                 |
     * | None                            | throw PermError                 |
     * +---------------------------------+---------------------------------+
     */
    switch (eval_score) {
    case SPF_SCORE_PASS:
        return SpfEvaluator_getScoreByQualifier(term->qualifier);   // match
    case SPF_SCORE_FAIL:
    case SPF_SCORE_SOFTFAIL:
    case SPF_SCORE_NEUTRAL:
        return SPF_SCORE_NULL;  // not match
    case SPF_SCORE_TEMPERROR:
        return SPF_SCORE_TEMPERROR; // throw TempError
    case SPF_SCORE_PERMERROR:
    case SPF_SCORE_NONE:
        return SPF_SCORE_PERMERROR; // throw PermError
    case SPF_SCORE_SYSERROR:
        return SPF_SCORE_SYSERROR;
    case SPF_SCORE_NULL:
    default:
        abort();
    }   // end switch
}   // end function: SpfEvaluator_evalMechInclude

/*
 * "a" メカニズムと "mx" メカニズムの共通部分を実装する関数
 */
static SpfScore
SpfEvaluator_evalByALookup(SpfEvaluator *self, const char *domain, const SpfTerm *term,
                           bool count_void_lookup)
{
    size_t n;
    switch (self->sa_family) {
    case AF_INET:;
        DnsAResponse *resp4;
        dns_stat_t query4_stat = DnsResolver_lookupA(self->resolver, domain, &resp4);
        if (DNS_STAT_NOERROR != query4_stat) {
            if (count_void_lookup
                && SPF_SCORE_PERMERROR == SpfEvaluator_incrementVoidLookupCounter(self,
                                                                                  query4_stat)) {
                LogDnsError("a", domain, "SPF \'a\' mechanism", "VOIDLOOKUP_EXCEEDS");
                return SPF_SCORE_PERMERROR;
            }   // end if
            LogDnsError("a", domain, "SPF \'a\' mechanism",
                        DnsResolver_getErrorSymbol(self->resolver));
            return SpfEvaluator_mapMechDnsResponseToSpfScore(query4_stat);
        }   // end if

        for (n = 0; n < resp4->num; ++n) {
            if (0 == bitmemcmp(&(self->ipaddr.addr4), &(resp4->addr[n]), term->ip4cidr)) {
                DnsAResponse_free(resp4);
                return SpfEvaluator_getScoreByQualifier(term->qualifier);
            }   // end if
        }   // end for
        DnsAResponse_free(resp4);
        break;

    case AF_INET6:;
        DnsAaaaResponse *resp6;
        dns_stat_t query6_stat = DnsResolver_lookupAaaa(self->resolver, domain, &resp6);
        if (DNS_STAT_NOERROR != query6_stat) {
            if (count_void_lookup
                && SPF_SCORE_PERMERROR == SpfEvaluator_incrementVoidLookupCounter(self,
                                                                                  query6_stat)) {
                LogDnsError("aaaa", domain, "SPF \'a\' mechanism", "VOIDLOOKUP_EXCEEDS");
                return SPF_SCORE_PERMERROR;
            }   // end if
            LogDnsError("aaaa", domain, "SPF \'a\' mechanism",
                        DnsResolver_getErrorSymbol(self->resolver));
            return SpfEvaluator_mapMechDnsResponseToSpfScore(query6_stat);
        }   // end if

        for (n = 0; n < resp6->num; ++n) {
            if (0 == bitmemcmp(&(self->ipaddr.addr6), &(resp6->addr[n]), term->ip6cidr)) {
                DnsAaaaResponse_free(resp6);
                return SpfEvaluator_getScoreByQualifier(term->qualifier);
            }   // end if
        }   // end for
        DnsAaaaResponse_free(resp6);
        break;

    default:
        abort();
    }   // end if

    return SPF_SCORE_NULL;
}   // end function: SpfEvaluator_evalByALookup

static SpfScore
SpfEvaluator_evalMechA(SpfEvaluator *self, const SpfTerm *term)
{
    assert(SPF_TERM_PARAM_DOMAINSPEC == term->attr->param_type);

    SpfScore score = SpfEvaluator_checkMaliceOfDualCidrLength(self, term);
    if (score != SPF_SCORE_NULL) {
        return score;
    }   // end if

    const char *domain = SpfEvaluator_getTargetName(self, term);
    return SpfEvaluator_evalByALookup(self, domain, term, true);
}   // end function: SpfEvaluator_evalMechA

static SpfScore
SpfEvaluator_evalMechMx(SpfEvaluator *self, const SpfTerm *term)
{
    assert(SPF_TERM_PARAM_DOMAINSPEC == term->attr->param_type);

    SpfScore score = SpfEvaluator_checkMaliceOfDualCidrLength(self, term);
    if (score != SPF_SCORE_NULL) {
        return score;
    }   // end if

    const char *domain = SpfEvaluator_getTargetName(self, term);
    DnsMxResponse *respmx;
    dns_stat_t mxquery_stat = DnsResolver_lookupMx(self->resolver, domain, &respmx);
    if (DNS_STAT_NOERROR != mxquery_stat) {
        if (SPF_SCORE_PERMERROR == SpfEvaluator_incrementVoidLookupCounter(self, mxquery_stat)) {
            LogDnsError("mx", term->querydomain, "SPF \'mx\' mechanism", "VOIDLOOKUP_EXCEEDS");
            return SPF_SCORE_PERMERROR;
        }   // end if
        LogDnsError("mx", domain, "SPF \'mx\' mechanism",
                    DnsResolver_getErrorSymbol(self->resolver));
        return SpfEvaluator_mapMechDnsResponseToSpfScore(mxquery_stat);
    }   // end if

    /*
     * [RFC4408] 5.4.
     * check_host() first performs an MX lookup on the <target-name>.  Then
     * it performs an address lookup on each MX name returned.  The <ip> is
     * compared to each returned IP address.  To prevent Denial of Service
     * (DoS) attacks, more than 10 MX names MUST NOT be looked up during the
     * evaluation of an "mx" mechanism (see Section 10).  If any address
     * matches, the mechanism matches.
     */
    for (size_t n = 0; n < MIN(respmx->num, self->policy->max_mxrr_per_mxmech); ++n) {
        SpfScore score = SpfEvaluator_evalByALookup(self, respmx->exchange[n]->domain, term, false);
        if (SPF_SCORE_NULL != score) {
            DnsMxResponse_free(respmx);
            return score;
        }   // end if
    }   // end for
    DnsMxResponse_free(respmx);
    return SPF_SCORE_NULL;
}   // end function: SpfEvaluator_evalMechMx

/**
 * @param self SpfEvaluator object.
 * @param revdomain
 * @return 1 if IP addresses match.
 *         0 if IP addresses doesn't match.
 *         -1 if DNS error occurred.
 */
static int
SpfEvaluator_isValidatedDomainName4(const SpfEvaluator *self, const char *revdomain)
{
    DnsAResponse *resp4;
    dns_stat_t query_stat = DnsResolver_lookupA(self->resolver, revdomain, &resp4);
    if (DNS_STAT_NOERROR != query_stat) {
        LogDnsError("a", revdomain, "SPF domain validation, ignored",
                    DnsResolver_getErrorSymbol(self->resolver));
        return -1;
    }   // end if
    for (size_t m = 0; m < resp4->num; ++m) {
        if (0 == memcmp(&(resp4->addr[m]), &(self->ipaddr.addr4), NS_INADDRSZ)) {
            DnsAResponse_free(resp4);
            return 1;
        }   // end if
    }   // end for
    DnsAResponse_free(resp4);
    return 0;
}   // end function: SpfEvaluator_isValidatedDomainName4

/**
 * @param self SpfEvaluator object.
 * @param revdomain
 * @return 1 if IP addresses match.
 *         0 if IP addresses doesn't match.
 *         -1 if DNS error occurred.
 */
static int
SpfEvaluator_isValidatedDomainName6(const SpfEvaluator *self, const char *revdomain)
{
    DnsAaaaResponse *resp6;
    dns_stat_t query_stat = DnsResolver_lookupAaaa(self->resolver, revdomain, &resp6);
    if (DNS_STAT_NOERROR != query_stat) {
        LogDnsError("aaaa", revdomain, "SPF domain validation, ignored",
                    DnsResolver_getErrorSymbol(self->resolver));
        return -1;
    }   // end if
    for (size_t m = 0; m < resp6->num; ++m) {
        if (0 == memcmp(&(resp6->addr[m]), &(self->ipaddr.addr6), NS_IN6ADDRSZ)) {
            DnsAaaaResponse_free(resp6);
            return 1;
        }   // end if
    }   // end for
    DnsAaaaResponse_free(resp6);
    return 0;
}   // end function: SpfMacro_isValidatedDomainName6

/*
 * @param self SpfEvaluator object.
 * @param revdomain
 * @return 1 if IP addresses match.
 *         0 if IP addresses doesn't match.
 *         -1 if DNS error occurred.
 */
int
SpfEvaluator_isValidatedDomainName(const SpfEvaluator *self, const char *revdomain)
{
    switch (self->sa_family) {
    case AF_INET:
        return SpfEvaluator_isValidatedDomainName4(self, revdomain);
    case AF_INET6:
        return SpfEvaluator_isValidatedDomainName6(self, revdomain);
    default:
        abort();
    }   // end switch
}   // end function: SpfEvaluator_isValidatedDomainName

static SpfScore
SpfEvaluator_evalMechPtr(SpfEvaluator *self, const SpfTerm *term)
{
    assert(SPF_TERM_PARAM_DOMAINSPEC == term->attr->param_type);
    const char *domain = SpfEvaluator_getTargetName(self, term);
    DnsPtrResponse *respptr;
    dns_stat_t ptrquery_stat =
        DnsResolver_lookupPtr(self->resolver, self->sa_family, &(self->ipaddr), &respptr);
    if (DNS_STAT_NOERROR != ptrquery_stat) {
        /*
         * [RFC4408] 5.5.
         * If a DNS error occurs while doing the PTR RR lookup, then this
         * mechanism fails to match.
         */
        char addrbuf[INET6_ADDRSTRLEN];
        (void) inet_ntop(self->sa_family, &(self->ipaddr), addrbuf, sizeof(addrbuf));

        if (SPF_SCORE_PERMERROR == SpfEvaluator_incrementVoidLookupCounter(self, ptrquery_stat)) {
            LogDnsError("ptr", addrbuf, "SPF \'ptr\' mechanism", "VOIDLOOKUP_EXCEEDS");
            return SPF_SCORE_PERMERROR;
        }   // end if

        LogDnsError("ptr", addrbuf, "SPF \'ptr\' mechanism, ignored",
                    DnsResolver_getErrorSymbol(self->resolver));
        return SPF_SCORE_NULL;
    }   // end if

    /*
     * [RFC4408] 5.5.
     * First, the <ip>'s name is looked up using this procedure: perform a
     * DNS reverse-mapping for <ip>, looking up the corresponding PTR record
     * in "in-addr.arpa." if the address is an IPv4 one and in "ip6.arpa."
     * if it is an IPv6 address.  For each record returned, validate the
     * domain name by looking up its IP address.  To prevent DoS attacks,
     * more than 10 PTR names MUST NOT be looked up during the evaluation of
     * a "ptr" mechanism (see Section 10).  If <ip> is among the returned IP
     * addresses, then that domain name is validated.
     */
    size_t resp_num_limit = MIN(respptr->num, self->policy->max_ptrrr_per_ptrmech);
    for (size_t n = 0; n < resp_num_limit; ++n) {
        // アルゴリズムをよく読むと validated domain が <target-name> で終わっているかどうかの判断を
        // 先におこなった方が DNS ルックアップの回数が少なくて済む場合があることがわかる.
        /*
         * [RFC4408] 5.5.
         * Check all validated domain names to see if they end in the
         * <target-name> domain.  If any do, this mechanism matches.  If no
         * validated domain name can be found, or if none of the validated
         * domain names end in the <target-name>, this mechanism fails to match.
         */
        if (!InetDomain_isParent(domain, respptr->domain[n])) {
            continue;
        }   // end if

        int validation_stat = SpfEvaluator_isValidatedDomainName(self, respptr->domain[n]);
        /*
         * [RFC4408] 5.5.
         * If a DNS error occurs while doing an A RR
         * lookup, then that domain name is skipped and the search continues.
         */
        if (1 == validation_stat) {
            DnsPtrResponse_free(respptr);
            return SpfEvaluator_getScoreByQualifier(term->qualifier);
        }   // end if
    }   // end for
    DnsPtrResponse_free(respptr);
    return SPF_SCORE_NULL;
}   // end function: SpfEvaluator_evalMechPtr

static SpfScore
SpfEvaluator_evalMechIp4(const SpfEvaluator *self, const SpfTerm *term)
{
    assert(SPF_TERM_PARAM_IP4 == term->attr->param_type);
    SpfScore score = SpfEvaluator_checkMaliceOfIp4CidrLength(self, term);
    if (score != SPF_SCORE_NULL) {
        return score;
    }   // end if
    return (AF_INET == self->sa_family
            && 0 == bitmemcmp(&(self->ipaddr.addr4), &(term->param.addr4), term->ip4cidr))
        ? SpfEvaluator_getScoreByQualifier(term->qualifier) : SPF_SCORE_NULL;
}   // end function: SpfEvaluator_evalMechIp4

static SpfScore
SpfEvaluator_evalMechIp6(const SpfEvaluator *self, const SpfTerm *term)
{
    assert(SPF_TERM_PARAM_IP6 == term->attr->param_type);
    SpfScore score = SpfEvaluator_checkMaliceOfIp6CidrLength(self, term);
    if (score != SPF_SCORE_NULL) {
        return score;
    }   // end if
    return (AF_INET6 == self->sa_family
            && 0 == bitmemcmp(&(self->ipaddr.addr6), &(term->param.addr6), term->ip6cidr))
        ? SpfEvaluator_getScoreByQualifier(term->qualifier) : SPF_SCORE_NULL;
}   // end function: SpfEvaluator_evalMechIp6

static SpfScore
SpfEvaluator_evalMechExists(SpfEvaluator *self, const SpfTerm *term)
{
    assert(SPF_TERM_PARAM_DOMAINSPEC == term->attr->param_type);
    DnsAResponse *resp4;
    dns_stat_t aquery_stat = DnsResolver_lookupA(self->resolver, term->querydomain, &resp4);
    if (DNS_STAT_NOERROR != aquery_stat) {
        if (SPF_SCORE_PERMERROR == SpfEvaluator_incrementVoidLookupCounter(self, aquery_stat)) {
            LogDnsError("a", term->querydomain, "SPF \'exist\' mechanism", "VOIDLOOKUP_EXCEEDS");
            return SPF_SCORE_PERMERROR;
        }   // end if
        LogDnsError("a", term->querydomain, "SPF \'exist\' mechanism",
                    DnsResolver_getErrorSymbol(self->resolver));
        return SpfEvaluator_mapMechDnsResponseToSpfScore(aquery_stat);
    }   // end if

    size_t num = resp4->num;
    DnsAResponse_free(resp4);
    return (0 < num) ? SpfEvaluator_getScoreByQualifier(term->qualifier) : SPF_SCORE_NULL;
}   // end function: SpfEvaluator_evalMechExists

static SpfScore
SpfEvaluator_evalModRedirect(SpfEvaluator *self, const SpfTerm *term)
{
    assert(SPF_TERM_PARAM_DOMAINSPEC == term->attr->param_type);
    SpfScore incr_stat = SpfEvaluator_incrementDnsMechCounter(self);
    if (SPF_SCORE_NULL != incr_stat) {
        return incr_stat;
    }   // end if
    ++(self->redirect_depth);
    SpfScore eval_score = SpfEvaluator_checkHost(self, term->querydomain, true);
    --(self->redirect_depth);
    /*
     * [RFC4408] 6.1.
     * The result of this new evaluation of check_host() is then considered
     * the result of the current evaluation with the exception that if no
     * SPF record is found, or if the target-name is malformed, the result
     * is a "PermError" rather than "None".
     */
    return SPF_SCORE_NONE == eval_score ? SPF_SCORE_PERMERROR : eval_score;
}   // end function: SpfEvaluator_evalModRedirect

static SpfStat
SpfEvaluator_evalModExplanation(SpfEvaluator *self, const SpfTerm *term)
{
    /*
     * [RFC4408] 6.2.
     * If <domain-spec> is empty, or there are any DNS processing errors
     * (any RCODE other than 0), or if no records are returned, or if more
     * than one record is returned, or if there are syntax errors in the
     * explanation string, then proceed as if no exp modifier was given.
     */

    assert(SPF_TERM_PARAM_DOMAINSPEC == term->attr->param_type);

    DnsTxtResponse *resptxt;
    dns_stat_t txtquery_stat = DnsResolver_lookupTxt(self->resolver, term->querydomain, &resptxt);
    if (DNS_STAT_NOERROR != txtquery_stat) {
        LogDnsError("txt", term->querydomain, "SPF \'exp\' modifier, ignored",
                    DnsResolver_getErrorSymbol(self->resolver));
        return SPF_STAT_OK;
    }   // end if

    if (1 != resptxt->num) {
        DnsTxtResponse_free(resptxt);
        return SPF_STAT_OK;
    }   // end if

    SpfStat expand_stat = SpfEvaluator_setExplanation(self, term->querydomain, resptxt->data[0]);
    DnsTxtResponse_free(resptxt);
    return expand_stat;
}   // end function: SpfEvaluator_evalModExplanation

static SpfScore
SpfEvaluator_evalMechanism(SpfEvaluator *self, const SpfTerm *term)
{
    assert(NULL != term);
    assert(NULL != term->attr);

    if (term->attr->involve_dnslookup) {
        SpfScore incr_stat = SpfEvaluator_incrementDnsMechCounter(self);
        if (SPF_SCORE_NULL != incr_stat) {
            return incr_stat;
        }   // end if
    }   // end if

    switch (term->attr->type) {
    case SPF_TERM_MECH_ALL:
        return SpfEvaluator_evalMechAll(self, term);
    case SPF_TERM_MECH_INCLUDE:
        return SpfEvaluator_evalMechInclude(self, term);
    case SPF_TERM_MECH_A:
        return SpfEvaluator_evalMechA(self, term);
    case SPF_TERM_MECH_MX:
        return SpfEvaluator_evalMechMx(self, term);
    case SPF_TERM_MECH_PTR:
        return SpfEvaluator_evalMechPtr(self, term);
    case SPF_TERM_MECH_IP4:
        return SpfEvaluator_evalMechIp4(self, term);
    case SPF_TERM_MECH_IP6:
        return SpfEvaluator_evalMechIp6(self, term);
    case SPF_TERM_MECH_EXISTS:
        return SpfEvaluator_evalMechExists(self, term);
    default:
        abort();
    }   // end switch
}   // end function: SpfEvaluator_evalMechanism

static SpfScore
SpfEvaluator_checkDomain(const SpfEvaluator *self, const char *domain)
{
    /*
     * 引数 <domain> の検証
     *
     * [RFC4408] 4.3.
     * If the <domain> is malformed (label longer than 63 characters, zero-
     * length label not at the end, etc.) or is not a fully qualified domain
     * name, or if the DNS lookup returns "domain does not exist" (RCODE 3),
     * check_host() immediately returns the result "None".
     */
    const char *p = domain;
    const char *domain_tail = STRTAIL(domain);
    while (p < domain_tail) {
        // 同時に文字種のチェック. 2821-Domain だとキツいのでちょっと緩め.
        int label_len = XSkip_atextBlock(p, domain_tail, &p);
        if (label_len <= 0) {
            break;
        } else if ((int) self->policy->max_label_len < label_len) {
            SpfLogPermFail
                ("label length of <domain> argument of check_host exceeds its limit: length=%u, limit=%u, domain(256)=%.256s",
                 (unsigned int) label_len, self->policy->max_label_len, domain);
            return SPF_SCORE_NONE;
        }   // end if
        if (0 >= XSkip_char(p, domain_tail, '.', &p)) {
            /*
             * <domain-spec> may end with '.' (dot, 0x2e)
             * [RFC4408] 8.1.
             * domain-spec      = macro-string domain-end
             * domain-end       = ( "." toplabel [ "." ] ) / macro-expand
             */
            break;
        }   // end if
    }   // end while
    if (domain_tail != p) {
        SpfLogPermFail("<domain> argument of check_host doesn't match domain-name: domain=%s",
                       domain);
        return SPF_SCORE_NONE;
    }   // end if

    // "include" mechanism や "redirect=" modifier でループを形成していないかチェックする.
    if (0 <= StrArray_linearSearchIgnoreCase(self->domain, domain)) {
        SpfLogPermFail("evaluation loop detected: domain=%s", domain);
        return SPF_SCORE_PERMERROR;
    }   // end if

    return SPF_SCORE_NULL;
}   // end function: SpfEvaluator_checkDomain

static SpfScore
SpfEvaluator_evalDirectives(SpfEvaluator *self, const PtrArray *directives)
{
    const char *domain = SpfEvaluator_getDomain(self);
    unsigned int directive_num = PtrArray_getCount(directives);
    for (unsigned int i = 0; i < directive_num; ++i) {
        SpfTerm *term = PtrArray_get(directives, i);
        SpfScore eval_score = SpfEvaluator_evalMechanism(self, term);
        if (SPF_SCORE_NULL != eval_score) {
            LogDebug("mechanism match: domain=%s, mech%02u=%s, score=%s",
                     domain, i, term->attr->name, SpfEnum_lookupScoreByValue(eval_score));
            return eval_score;
        }   // end if
        LogDebug("mechanism not match: domain=%s, mech_no=%u, mech=%s",
                 domain, i, term->attr->name);
    }   // end if
    return SPF_SCORE_NULL;
}   // end function: SpfEvaluator_evalDirectives

static SpfScore
SpfEvaluator_evalLocalPolicy(SpfEvaluator *self)
{
    // 再帰評価 (include や redirect) の内側にいない場合のみ, ローカルポリシーの評価をおこなう
    if (0 < SpfEvaluator_getDepth(self) || NULL == self->policy->local_policy
        || self->local_policy_mode) {
        return SPF_SCORE_NULL;
    }   // end if

    LogDebug("evaluating local policy: policy=%s", self->policy->local_policy);
    // SPF/SIDF 評価過程で遭遇した DNS をひくメカニズムのカウンタをクリア
    SpfRecord *local_policy_record = NULL;
    SpfStat build_stat = SpfRecord_build(self, self->scope, self->policy->local_policy,
                                         STRTAIL(self->policy->local_policy),
                                         &local_policy_record);
    if (SPF_STAT_OK != build_stat) {
        SpfLogConfigError("failed to build local policy record: policy=%s",
                          self->policy->local_policy);
        return SPF_SCORE_NULL;
    }   // end if
    self->dns_mech_count = 0;   // 本物のレコード評価中に遭遇した DNS ルックアップを伴うメカニズムの数は忘れる
    self->local_policy_mode = true; // ローカルポリシー評価中に, さらにローカルポリシーを適用して無限ループに入らないようにフラグを立てる.
    SpfScore local_policy_score =
        SpfEvaluator_evalDirectives(self, local_policy_record->directives);
    self->local_policy_mode = false;
    SpfRecord_free(local_policy_record);

    switch (local_policy_score) {
    case SPF_SCORE_PERMERROR:
    case SPF_SCORE_TEMPERROR:
        // ローカルポリシー評価中の temperror, permerror は無視する
        LogDebug("ignoring local policy score: score=%s",
                 SpfEnum_lookupScoreByValue(local_policy_score));
        return SPF_SCORE_NULL;
    default:
        LogDebug("applying local policy score: score=%s",
                 SpfEnum_lookupScoreByValue(local_policy_score));
        return local_policy_score;
    }   // end switch
}   // end function: SpfEvaluator_evalLocalPolicy

/**
 * The check_host() Function as defined in Section 4 of RFC4408
 * @param self SpfEvaluator object.
 * @param domain <domain> parameter of the check_host() function
 */
static SpfScore
SpfEvaluator_checkHost(SpfEvaluator *self, const char *domain, bool count_void_lookup)
{
    // check <domain> parameter
    SpfScore precond_score = SpfEvaluator_checkDomain(self, domain);
    if (SPF_SCORE_NULL != precond_score) {
        return precond_score;
    }   // end if

    // register <domain> parameter
    SpfStat push_stat = SpfEvaluator_pushDomain(self, domain);
    if (SPF_STAT_OK != push_stat) {
        return SPF_SCORE_SYSERROR;
    }   // end if

    SpfRecord *record = NULL;
    SpfScore lookup_score =
        SpfEvaluator_lookupRecord(self, SpfEvaluator_getDomain(self), count_void_lookup, &record);
    if (SPF_SCORE_NULL != lookup_score) {
        SpfEvaluator_popDomain(self);
        return lookup_score;
    }   // end if

    // mechanism evaluation
    SpfScore eval_score = SpfEvaluator_evalDirectives(self, record->directives);
    if (SPF_SCORE_NULL != eval_score) {
        /*
         * SpfEvalPolicy で "exp=" を取得するようの指定されている場合に "exp=" を取得する.
         * ただし, 以下の点に注意する:
         * - include メカニズム中の exp= は評価しない.
         * - redirect 評価中に元のドメインの exp= は評価しない.
         * [RFC4408] 6.2.
         * Note: During recursion into an "include" mechanism, an exp= modifier
         * from the <target-name> MUST NOT be used.  In contrast, when executing
         * a "redirect" modifier, an exp= modifier from the original domain MUST
         * NOT be used.
         *
         * <target-name> は メカニズムの引数で指定されている <domain-spec>,
         * 指定されていない場合は check_host() 関数の <domain>.
         * [RFC4408] 4.8.
         * Several of these mechanisms and modifiers have a <domain-spec>
         * section.  The <domain-spec> string is macro expanded (see Section 8).
         * The resulting string is the common presentation form of a fully-
         * qualified DNS name: a series of labels separated by periods.  This
         * domain is called the <target-name> in the rest of this document.
         */
        if (self->policy->lookup_exp && SPF_SCORE_FAIL == eval_score
            && 0 == self->include_depth && NULL != record->modifiers.exp) {
            (void) SpfEvaluator_evalModExplanation(self, record->modifiers.exp);
        }   // end if
        goto finally;
    }   // end if

    /*
     * レコード中の全てのメカニズムにマッチしなかった場合
     * [RFC4408] 4.7.
     * If none of the mechanisms match and there is no "redirect" modifier,
     * then the check_host() returns a result of "Neutral", just as if
     * "?all" were specified as the last directive.  If there is a
     * "redirect" modifier, check_host() proceeds as defined in Section 6.1.
     */

    // "redirect=" modifier evaluation
    if (NULL != record->modifiers.rediect) {
        LogDebug("redirect: from=%s, to=%s", domain, record->modifiers.rediect->param.domain);
        eval_score = SpfEvaluator_evalModRedirect(self, record->modifiers.rediect);
        goto finally;
    }   // end if

    eval_score = SpfEvaluator_evalLocalPolicy(self);
    if (SPF_SCORE_NULL != eval_score) {
        // exp= を評価する条件は directive によってスコアが決定する場合とほぼ同じ.
        // 違いは local_policy_explanation を使用する点.
        if (self->policy->lookup_exp && SPF_SCORE_FAIL == eval_score
            && 0 == self->include_depth && NULL != self->policy->local_policy_explanation) {
            // local policy 専用の explanation をセットする.
            (void) SpfEvaluator_setExplanation(self, domain,
                                               self->policy->local_policy_explanation);
        }   // end if
        goto finally;
    }   // end if

    // returns "Neutral" as default socre
    eval_score = SPF_SCORE_NEUTRAL;
    LogDebug("default score applied: domain=%s", domain);

  finally:
    SpfEvaluator_popDomain(self);
    SpfRecord_free(record);
    return eval_score;
}   // end function: SpfEvaluator_checkHost

/**
 * HELO は指定必須. sender が指定されていない場合, postmaster@(HELOとして指定したドメイン) を sender として使用する.
 * @return SPF_SCORE_NULL: 引数がセットされていない.
 *         SPF_SCORE_SYSERROR: メモリの確保に失敗した.
 *         それ以外の場合は評価結果.
 */
SpfScore
SpfEvaluator_eval(SpfEvaluator *self, SpfRecordScope scope)
{
    assert(NULL != self);

    if (SPF_SCORE_NULL != self->score) {
        return self->score;
    }   // end if

    self->scope = scope;
    self->dns_mech_count = 0;
    self->void_lookup_count = 0;
    if (0 == self->sa_family || NULL == self->helo_domain) {
        return SPF_SCORE_NULL;
    }   // end if
    if (NULL == self->sender) {
        /*
         * [RFC4408] 4.3.
         * If the <sender> has no localpart, substitute the string "postmaster"
         * for the localpart.
         */
        self->sender = InetMailbox_build(SPF_EVAL_DEFAULT_LOCALPART, self->helo_domain);
        if (NULL == self->sender) {
            LogNoResource();
            return SPF_SCORE_SYSERROR;
        }   // end if
        self->is_sender_context = false;
    } else {
        self->is_sender_context = true;
    }   // end if
    self->redirect_depth = 0;
    self->include_depth = 0;
    self->score = SpfEvaluator_checkHost(self, InetMailbox_getDomain(self->sender), false);
    return self->score;
}   // end function: SpfEvaluator_eval

/**
 * This function sets an IP address to the SpfEvaluator object via sockaddr structure.
 * The IP address is used as <ip> parameter of check_host function.
 * @param self SpfEvaluator object.
 * @param sa_family address family. AF_INET for IPv4, AF_INET6 for IPv6.
 * @param addr a pointer to the sockaddr_in structure for IPv4,
 *             sockaddr_in6 structure for IPv6.
 * @return true on successful completion, false otherwise.
 *         If sa_family is specified correctly, this function won't fail.
 */
bool
SpfEvaluator_setIpAddr(SpfEvaluator *self, sa_family_t sa_family, const struct sockaddr *addr)
{
    assert(NULL != self);
    assert(NULL != addr);

    self->sa_family = sa_family;
    switch (sa_family) {
    case AF_INET:
        memcpy(&(self->ipaddr.addr4), &(((const struct sockaddr_in *) addr)->sin_addr),
               sizeof(struct in_addr));
        return true;
    case AF_INET6:
        memcpy(&(self->ipaddr.addr6), &(((const struct sockaddr_in6 *) addr)->sin6_addr),
               sizeof(struct in6_addr));
        return true;
    default:
        return false;
    }   // end switch
}   // end function: SpfEvaluator_setIpAddr

/**
 * This function sets an IP address to the SpfEvaluator object with string representation.
 * The IP address is used as <ip> parameter of check_host function.
 * @param self SpfEvaluator object.
 * @param sa_family address family. AF_INET for IPv4, AF_INET6 for IPv6.
 * @param address a null-terminated string represents an IP address.
 * @return true on successful completion, false otherwise.
 *         If sa_family is specified correctly, this function won't fail.
 */
bool
SpfEvaluator_setIpAddrString(SpfEvaluator *self, sa_family_t sa_family, const char *address)
{
    assert(NULL != self);
    assert(NULL != address);

    self->sa_family = sa_family;
    switch (sa_family) {
    case AF_INET:
        return bool_cast(1 == inet_pton(AF_INET, address, &(self->ipaddr.addr4)));
    case AF_INET6:
        return bool_cast(1 == inet_pton(AF_INET6, address, &(self->ipaddr.addr6)));
    default:
        return false;
    }   // end switch
}   // end function: SpfEvaluator_setIpAddrString

/**
 * 送信者のメールアドレスを SpfEvaluator にセットする.
 * check_host() 関数の引数 <sender> やマクロの展開の際に用いられる.
 * @return 成功した場合は true, メモリの確保に失敗した場合は false.
 */
bool
SpfEvaluator_setSender(SpfEvaluator *self, const InetMailbox *sender)
{
    assert(NULL != self);

    InetMailbox *mailbox = NULL;
    if (NULL != sender) {
        mailbox = InetMailbox_duplicate(sender);
        if (NULL == mailbox) {
            return false;
        }   // end if
    }   // end if

    InetMailbox_free(self->sender);
    self->sender = mailbox;
    return true;
}   // end function: SpfEvaluator_setSender

/**
 * HELO ドメインを SpfEvaluator にセットする.
 * <sender> がセットされていない場合に check_host() 関数の引数 <sender> として使用される.
 * また, マクロの展開の際にも用いられる.
 * @return 成功した場合は true, メモリの確保に失敗した場合は false.
 */
bool
SpfEvaluator_setHeloDomain(SpfEvaluator *self, const char *domain)
{
    assert(NULL != self);

    char *tmp = NULL;
    if (NULL != domain && NULL == (tmp = strdup(domain))) {
        return false;
    }   // end if
    free(self->helo_domain);
    self->helo_domain = tmp;
    return true;
}   // end function: SpfEvaluator_setHeloDomain

void
SpfEvaluator_reset(SpfEvaluator *self)
{
    assert(NULL != self);
    self->scope = SPF_RECORD_SCOPE_NULL;
    self->sa_family = 0;
    memset(&(self->ipaddr), 0, sizeof(union ipaddr46));
    if (NULL != self->domain) {
        StrArray_reset(self->domain);
    }   // end if
    self->dns_mech_count = 0;
    self->void_lookup_count = 0;
    self->redirect_depth = 0;
    self->include_depth = 0;
    self->is_sender_context = false;
    self->local_policy_mode = false;
    if (NULL != self->xbuf) {
        XBuffer_reset(self->xbuf);
    }   // end if
    if (NULL != self->sender) {
        InetMailbox_free(self->sender);
        self->sender = NULL;
    }   // end if
    if (NULL != self->helo_domain) {
        free(self->helo_domain);
        self->helo_domain = NULL;
    }   // end if
    self->score = SPF_SCORE_NULL;
    if (NULL != self->explanation) {
        free(self->explanation);
        self->explanation = NULL;
    }   // end if
}   // end function: SpfEvaluator_reset

/**
 * release SpfEvaluator object
 * @param self SpfEvaluator object to release
 */
void
SpfEvaluator_free(SpfEvaluator *self)
{
    if (NULL == self) {
        return;
    }   // end if

    StrArray_free(self->domain);
    XBuffer_free(self->xbuf);
    InetMailbox_free(self->sender);
    free(self->helo_domain);
    free(self->explanation);
    free(self);
}   // end function: SpfEvaluator_free

/**
 * create SpfEvaluator object
 * @return initialized SpfEvaluator object, or NULL if memory allocation failed.
 */
SpfEvaluator *
SpfEvaluator_new(const SpfEvalPolicy *policy, DnsResolver *resolver)
{
    SpfEvaluator *self = (SpfEvaluator *) malloc(sizeof(SpfEvaluator));
    if (NULL == self) {
        return NULL;
    }   // end if
    memset(self, 0, sizeof(SpfEvaluator));
    self->domain = StrArray_new(0);
    if (NULL == self->domain) {
        goto cleanup;
    }   // end if
    self->xbuf = XBuffer_new(0);
    if (NULL == self->xbuf) {
        goto cleanup;
    }   // end if
    self->policy = policy;
    self->resolver = resolver;
    self->is_sender_context = false;
    self->local_policy_mode = false;
    self->score = SPF_SCORE_NULL;
    return self;

  cleanup:
    SpfEvaluator_free(self);
    return NULL;
}   // end function: SpfEvaluator_new
