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

#ifndef __SPF_H__
#define __SPF_H__

#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "inetmailbox.h"
#include "inetmailheaders.h"
#include "dnsresolv.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum SpfStat {
    SPF_STAT_OK = 0,
    SPF_STAT_NO_RESOURCE,
    SPF_STAT_RECORD_VERSION_MISMATCH,
    SPF_STAT_RECORD_UNSUPPORTED_MECHANISM,
    SPF_STAT_RECORD_UNSUPPORTED_MODIFIER,
    SPF_STAT_RECORD_UNSUPPORTED_QUALIFIER,
    SPF_STAT_RECORD_UNSUPPORTED_MACRO,
    SPF_STAT_RECORD_DELIMITER_DUPLICATED,
    SPF_STAT_RECORD_SYNTAX_VIOLATION,  // syntax violation that causes errors
    SPF_STAT_RECORD_NOT_MATCH, // status which is not an error but does not satisfy the syntax (internal use)
    SPF_STAT_RECORD_INVALID_CIDR_LENGTH,
    SPF_STAT_MALICIOUS_MACRO_EXPANSION,
    SPF_STAT_DNS_NO_DATA,
    SPF_STAT_DNS_HOST_NOT_FOUND,
    SPF_STAT_DNS_TRY_AGAIN,
    SPF_STAT_DNS_NO_RECOVERY,
} SpfStat;

typedef enum SpfRecordScope {
    SPF_RECORD_SCOPE_NULL = 0x0000,
    SPF_RECORD_SCOPE_SPF1 = 0x0001,
    SPF_RECORD_SCOPE_SPF2_MFROM = 0x0002,
    SPF_RECORD_SCOPE_SPF2_PRA = 0x0004,
    SPF_RECORD_SCOPE_UNKNOWN = 0x0008,
} SpfRecordScope;

typedef enum SpfScore {
    SPF_SCORE_NULL = 0,
    SPF_SCORE_NONE,
    SPF_SCORE_NEUTRAL,
    SPF_SCORE_PASS,
    SPF_SCORE_POLICY,
    SPF_SCORE_FAIL,
    SPF_SCORE_HARDFAIL = SPF_SCORE_FAIL,  // deprecated by RFC6577
    SPF_SCORE_SOFTFAIL,
    SPF_SCORE_TEMPERROR,
    SPF_SCORE_PERMERROR,
    SPF_SCORE_SYSERROR,    // mostly equals to memory allocation error
    SPF_SCORE_MAX, // the number of SpfScore enumeration constants
} SpfScore;

typedef enum SpfCustomAction {
    SPF_CUSTOM_ACTION_NULL = 0,
    SPF_CUSTOM_ACTION_SCORE_NONE = SPF_SCORE_NONE,
    SPF_CUSTOM_ACTION_SCORE_NEUTRAL = SPF_SCORE_NEUTRAL,
    SPF_CUSTOM_ACTION_SCORE_PASS = SPF_SCORE_PASS,
    SPF_CUSTOM_ACTION_SCORE_POLICY = SPF_SCORE_POLICY,
    SPF_CUSTOM_ACTION_SCORE_FAIL = SPF_SCORE_FAIL,
    SPF_CUSTOM_ACTION_SCORE_SOFTFAIL = SPF_SCORE_SOFTFAIL,
    SPF_CUSTOM_ACTION_SCORE_TEMPERROR = SPF_SCORE_TEMPERROR,
    SPF_CUSTOM_ACTION_SCORE_PERMERROR = SPF_SCORE_PERMERROR,
    SPF_CUSTOM_ACTION_LOGGING,
} SpfCustomAction;

typedef struct SpfEvalPolicy SpfEvalPolicy;
typedef struct SpfEvaluator SpfEvaluator;

// SpfEvalPolicy
extern SpfEvalPolicy *SpfEvalPolicy_new(void);
extern void SpfEvalPolicy_free(SpfEvalPolicy *self);
extern void SpfEvalPolicy_setSpfRRLookup(SpfEvalPolicy *self, bool flag);
extern SpfStat SpfEvalPolicy_setCheckingDomain(SpfEvalPolicy *self, const char *domain);
extern SpfStat SpfEvalPolicy_setLocalPolicyDirectives(SpfEvalPolicy *self, const char *policy);
extern SpfStat SpfEvalPolicy_setLocalPolicyExplanation(SpfEvalPolicy *self, const char *explanation);
extern void SpfEvalPolicy_setExplanationLookup(SpfEvalPolicy *self, bool flag);
extern void SpfEvalPolicy_setPlusAllDirectiveHandling(SpfEvalPolicy *self, SpfCustomAction action);
extern void SpfEvalPolicy_setVoidLookupLimit(SpfEvalPolicy *self, int void_lookup_limit);

// SpfEvaluator
extern SpfEvaluator *SpfEvaluator_new(const SpfEvalPolicy *policy, DnsResolver *resolver);
extern void SpfEvaluator_reset(SpfEvaluator *self);
extern void SpfEvaluator_free(SpfEvaluator *self);
extern bool SpfEvaluator_isSenderContext(const SpfEvaluator *self);
extern const InetMailbox *SpfEvaluator_getSender(const SpfEvaluator *self);
extern const char *SpfEvaluator_getEvaluatedDomain(const SpfEvaluator *self);
extern const char *SpfEvaluator_getExplanation(const SpfEvaluator *self);
extern SpfScore SpfEvaluator_eval(SpfEvaluator *self, SpfRecordScope scope);
extern bool SpfEvaluator_setSender(SpfEvaluator *self, const InetMailbox *sender);
extern bool SpfEvaluator_setHeloDomain(SpfEvaluator *self, const char *domain);
extern bool SpfEvaluator_setIpAddr(SpfEvaluator *self, sa_family_t sa_family,
                                  const struct sockaddr *addr);
extern bool SpfEvaluator_setIpAddrString(SpfEvaluator *self, sa_family_t sa_family,
                                        const char *address);

// SpfEnum
extern SpfScore SpfEnum_lookupScoreByKeyword(const char *keyword);
extern SpfScore SpfEnum_lookupScoreByKeywordSlice(const char *head, const char *tail);
extern const char *SpfEnum_lookupScoreByValue(SpfScore value);
extern const char *SpfEnum_lookupClassicScoreByValue(SpfScore value);

// SidfPra
extern bool SidfPra_extract(const InetMailHeaders *headers,
                            int *pra_index, InetMailbox **pra_mailbox);

#ifdef __cplusplus
}
#endif

#endif /* __SPF_H__ */
