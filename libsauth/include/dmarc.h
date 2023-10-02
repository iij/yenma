/*
 * Copyright (c) 2013-2018 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifndef __DMARC_H__
#define __DMARC_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "inetmailbox.h"
#include "dnsresolv.h"
#include "spf.h"
#include "dkim.h"
#include "configtypes.h"

// Enumerations
typedef enum DmarcScore {
    DMARC_SCORE_NULL = 0,
    DMARC_SCORE_NONE,
    DMARC_SCORE_PASS,
    DMARC_SCORE_BESTGUESSPASS,
    DMARC_SCORE_FAIL,
    DMARC_SCORE_POLICY,
    DMARC_SCORE_TEMPERROR,
    DMARC_SCORE_PERMERROR,
    DMARC_SCORE_MAX,    // the number of DmarcScore enumeration constants
} DmarcScore;

typedef enum DmarcReceiverPolicy {
    DMARC_RECEIVER_POLICY_NULL = 0,
    DMARC_RECEIVER_POLICY_NONE,
    DMARC_RECEIVER_POLICY_QUARANTINE,
    DMARC_RECEIVER_POLICY_REJECT,
} DmarcReceiverPolicy;

typedef struct DmarcAligner DmarcAligner;
typedef struct PublicSuffix PublicSuffix;

extern DkimStatus DmarcAligner_new(const PublicSuffix *publicsuffix, DnsResolver *resolver, VdmarcVerificationMode vdmarc_verification_mode, DmarcAligner **aligner);
extern void DmarcAligner_free(DmarcAligner *self);
extern DmarcScore DmarcAligner_check(DmarcAligner *self, const InetMailbox *author,
        const DkimVerifier *dkimverifier, SpfEvaluator *spfevaluator);
extern DmarcReceiverPolicy DmarcAligner_getReceiverPolicy(DmarcAligner *self, bool apply_sampling_rate);

extern const char *DmarcEnum_lookupScoreByValue(DmarcScore val);
extern DmarcScore DmarcEnum_lookupScoreByName(const char *keyword);
extern DmarcScore DmarcEnum_lookupScoreByNameSlice(const char *head, const char *tail);

DkimStatus PublicSuffix_build(const char *filename, PublicSuffix **publicsuffix);
void PublicSuffix_free(PublicSuffix *self);
extern const char *PublicSuffix_getOrganizationalDomain(const PublicSuffix *self, const char *domain);

#ifdef __cplusplus
}
#endif

#endif /* __DMARC_H__ */
