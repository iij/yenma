/*
 * Copyright (c) 2014-2018 Internet Initiative Japan Inc. All rights reserved.
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
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "inetdomain.h"
#include "dnsresolv.h"
#include "loghandler.h"
#include "spf.h"
#include "dkim.h"
#include "dmarc.h"
#include "dmarcrecord.h"

struct DmarcAligner {
    const char *authordomain;
    const char *orgl_authordomain;
    const PublicSuffix *publicsuffix;
    DnsResolver *resolver;
    const DkimVerifier *verifier;
    SpfEvaluator *evaluator;
    DmarcScore score;
    DmarcReceiverPolicy policy;

    DmarcRecord *record;
    DkimStatus record_stat;
};

static DmarcReceiverPolicy
DmarcReceiverPolicy_downgrade(DmarcReceiverPolicy policy)
{
    switch (policy) {
    case DMARC_RECEIVER_POLICY_REJECT:
        return DMARC_RECEIVER_POLICY_QUARANTINE;
    case DMARC_RECEIVER_POLICY_QUARANTINE:
        return DMARC_RECEIVER_POLICY_NONE;
    default:
        return policy;
    }   // end switch
}   // end function: DmarcReceiverPolicy_downgrade

static DkimStatus
DmarcAligner_retrieveRecord(DmarcAligner *self)
{
    if (DSTAT_OK == self->record_stat) {
        self->record_stat =
            DmarcRecord_discover(self->authordomain, self->publicsuffix, self->resolver,
                                 &self->record);
    }   // end if
    switch (self->record_stat) {
    case DSTAT_OK:
    case DSTAT_INFO_FINISHED:
        self->record_stat = DSTAT_INFO_FINISHED;
        return DSTAT_OK;
    case DSTAT_INFO_DNSRR_NOT_EXIST:
        /*
         * [RFC7489] 11.2.
         * Code:  none
         * ...
         * Meaning:  No DMARC policy record was published for the aligned
         *    identifier, or no aligned identifier could be extracted.
         */
        self->score = DMARC_SCORE_NONE;
        break;
    case DSTAT_TMPERR_DNS_ERROR_RESPONSE:
    case DSTAT_SYSERR_DNS_LOOKUP_FAILURE:
        /*
         * [RFC7489] 11.2.
         * Code:  temperror
         * ...
         * Meaning:  A temporary error occurred during DMARC evaluation.  A
         *   later attempt might produce a final result.
         */
        self->score = DMARC_SCORE_TEMPERROR;
        break;
    case DSTAT_SYSERR_NORESOURCE:
    case DSTAT_SYSERR_IMPLERROR:
        self->score = DMARC_SCORE_NULL;
        break;
    default:
        /*
         * [RFC7489] 11.2.
         * Code:  permerror
         * ...
         * Meaning:  A permanent error occurred during DMARC evaluation, such as
         *   encountering a syntactically incorrect DMARC record.  A later
         *   attempt is unlikely to produce a final result.
         */
        self->score = DMARC_SCORE_PERMERROR;
        break;
    }   // end switch
    return self->record_stat;
}   // end function: DmarcAligner_retrieveRecord

static DkimStatus
DmarcAligner_checkStrictly(DmarcAligner *self, const char *domain)
{
    if (InetDomain_equals(domain, self->authordomain)) {
        self->score = DMARC_SCORE_PASS;
        return DSTAT_INFO_FINISHED;
    }   // end if
    return DSTAT_OK;
}   // end function: DmarcAligner_checkStrictly

static DkimStatus
DmarcAligner_checkRelaxedly(DmarcAligner *self, const char *domain)
{
    const char *orgl_domain = PublicSuffix_getOrganizationalDomain(self->publicsuffix, domain);
    if (NULL != orgl_domain && InetDomain_equals(orgl_domain, self->orgl_authordomain)) {
        self->score = DMARC_SCORE_PASS;
        return DSTAT_INFO_FINISHED;
    }   // end if

    return DSTAT_OK;
}   // end function: DmarcAligner_checkRelaxedly

static DkimStatus
DmarcAligner_checkDkimAlignment(DmarcAligner *self, bool strict_mode)
{
    if (NULL == self->verifier) {
        return DSTAT_OK;
    }   // end if

    /*
     * [RFC7489] 3.1.1.
     * Note that a single email can contain multiple DKIM signatures, and it
     * is considered to be a DMARC "pass" if any DKIM signature is aligned
     * and verifies.
     */
    size_t signum = DkimVerifier_getFrameCount(self->verifier);
    for (size_t sigidx = 0; sigidx < signum; ++sigidx) {
        const DkimFrameResult *result = DkimVerifier_getFrameResult(self->verifier, sigidx);
        if (DKIM_BASE_SCORE_PASS != result->score || result->testing) {
            continue;
        }   // end if
        DkimStatus dstat =
                (strict_mode || DMARC_ALIGN_MODE_RELAXED != DmarcRecord_getDkimAlignmentMode(self->record))
                ? DmarcAligner_checkStrictly(self, result->sdid)
                : DmarcAligner_checkRelaxedly(self, result->sdid);
        if (DSTAT_OK != dstat) {
            return dstat;
        }   // end if
    }   // end for

    return DSTAT_OK;
}   // end function: DmarcAligner_checkDkimAlignment

static DkimStatus
DmarcAligner_checkSpfAlignment(DmarcAligner *self, bool strict_mode)
{
    if (NULL == self->evaluator) {
        return DSTAT_OK;
    }   // end if

    if (SPF_SCORE_PASS != SpfEvaluator_eval(self->evaluator, SPF_RECORD_SCOPE_SPF1)) {
        return DSTAT_OK;
    }   // end if

    const char *spf_auth_domain = SpfEvaluator_getEvaluatedDomain(self->evaluator);
    return (strict_mode || DMARC_ALIGN_MODE_RELAXED != DmarcRecord_getSpfAlignmentMode(self->record))
           ? DmarcAligner_checkStrictly(self, spf_auth_domain)
           : DmarcAligner_checkRelaxedly(self, spf_auth_domain);
}   // end function: DmarcAligner_checkSpfAlignment

static DkimStatus
DmarcAligner_checkImpl(DmarcAligner *self, bool strict_mode)
{
    DkimStatus dkim_stat = DmarcAligner_checkDkimAlignment(self, strict_mode);
    if (DSTAT_INFO_FINISHED == dkim_stat) {
        return dkim_stat;
    }   // end if

    return DmarcAligner_checkSpfAlignment(self, strict_mode);
}   // end function: DmarcAligner_checkImpl

DmarcScore
DmarcAligner_check(DmarcAligner *self, const InetMailbox *author,
                   const DkimVerifier *dkimverifier, SpfEvaluator *spfevaluator)
{
    assert(NULL != author);

    self->authordomain = InetMailbox_getDomain(author);
    self->verifier = dkimverifier;
    self->evaluator = spfevaluator;
    self->record = NULL;
    self->record_stat = DSTAT_OK;

    DkimStatus record_stat = DmarcAligner_retrieveRecord(self);
    if (DSTAT_OK != record_stat) {
        return self->score;
    }   // end if

    DkimStatus strict_stat = DmarcAligner_checkImpl(self, true);
    if (DSTAT_INFO_FINISHED == strict_stat) {
        return self->score;
    }   // end if

    self->orgl_authordomain =
        PublicSuffix_getOrganizationalDomain(self->publicsuffix, self->authordomain);
    if (NULL != self->orgl_authordomain) {
        DkimStatus relaxed_stat = DmarcAligner_checkImpl(self, false);
        if (DSTAT_INFO_FINISHED == relaxed_stat) {
            return self->score;
        }   // end if
    }   // end if

    /*
     * [RFC7489] 11.2.
     * Code:  fail
     * ...
     * Meaning:  A DMARC policy record was published for the aligned
     *   identifier, and none of the authentication mechanisms passed.
     */
    return self->score = DMARC_SCORE_FAIL;
}   // end function: DmarcAligner_check

DmarcReceiverPolicy
DmarcAligner_getReceiverPolicy(DmarcAligner *self, bool apply_sampling_rate)
{
    // check if DmarcAligner_check() is already called.
    if (DMARC_SCORE_NULL == self->score) {
        return DMARC_RECEIVER_POLICY_NULL;
    }   // end if

    if (DMARC_RECEIVER_POLICY_NULL != self->policy) {
        return self->policy;
    }   // end if

    if (NULL == self->record || NULL == self->authordomain) {
        return self->policy = DMARC_RECEIVER_POLICY_NONE;
    }   // end if

    switch (self->score) {
    case DMARC_SCORE_NULL: // DMARC evaluation is turned off.
    case DMARC_SCORE_NONE:
    case DMARC_SCORE_PASS:
    case DMARC_SCORE_TEMPERROR:    // memory allocation failure or DNS lookup failure
    case DMARC_SCORE_PERMERROR:    // DMARC record is (syntactically) broken.
        return self->policy = DMARC_RECEIVER_POLICY_NONE;

    case DMARC_SCORE_FAIL:;
        DmarcReceiverPolicy receiver_policy = DMARC_RECEIVER_POLICY_NULL;
        if (!InetDomain_equals(self->authordomain, DmarcRecord_getDomain(self->record))
            && DMARC_RECEIVER_POLICY_NULL != DmarcRecord_getSubdomainPolicy(self->record)) {
            receiver_policy = DmarcRecord_getSubdomainPolicy(self->record);
        } else {
            receiver_policy = DmarcRecord_getReceiverPolicy(self->record);
        }   // end if

        if (apply_sampling_rate
            && DmarcRecord_getSamplingRate(self->record) <= (uint8_t) (random() % 100)) {
            receiver_policy = DmarcReceiverPolicy_downgrade(receiver_policy);
        }   // end if

        return self->policy = receiver_policy;

    default:
        abort();
    }   // end switch

    return DMARC_RECEIVER_POLICY_NULL;  // never reach here
}   // end function: DmarcAligner_getReceiverPolicy

void
DmarcAligner_free(DmarcAligner *self)
{
    if (NULL == self) {
        return;
    }   // end if

    DmarcRecord_free(self->record);
    free(self);
}   // end function: DmarcAligner_free

DkimStatus
DmarcAligner_new(const PublicSuffix *publicsuffix, DnsResolver *resolver, DmarcAligner **aligner)
{
    DmarcAligner *self = (DmarcAligner *) malloc(sizeof(DmarcAligner));
    if (NULL == self) {
        return DSTAT_SYSERR_NORESOURCE;
    }   // end if

    memset(self, 0, sizeof(DmarcAligner));
    self->score = DMARC_SCORE_NULL;
    self->policy = DMARC_RECEIVER_POLICY_NULL;
    self->publicsuffix = publicsuffix;
    self->resolver = resolver;

    *aligner = self;
    return DSTAT_OK;
}   // end function: DmarcAligner_new
