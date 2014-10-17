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

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <syslog.h>

#include "spf.h"
#include "spfevalpolicy.h"

#define SPF_EVAL_POLICY_DEFAULT_MACRO_EXPANSION_LIMIT 10240
#define SPF_EVAL_MAX_DNSMECH 10
#define SPF_EVAL_MAX_MXMECH_MXRR 10
#define SPF_EVAL_MAX_PTRMECH_PTRRR 10
#define SPF_EVAL_VOID_LOOKUP_LIMIT 2
#define SPF_EVAL_LABEL_MAX_LENGTH 63

/**
 * create SpfEvalPolicy object
 * @return initialized SpfEvalPolicy object, or NULL if memory allocation failed.
 */
SpfEvalPolicy *
SpfEvalPolicy_new(void)
{
    SpfEvalPolicy *self = (SpfEvalPolicy *) malloc(sizeof(SpfEvalPolicy));
    if (NULL == self) {
        return NULL;
    }   // end if
    self->lookup_spf_rr = false;
    self->lookup_exp = false;
    self->checking_domain = NULL;
    self->local_policy = NULL;
    self->local_policy_explanation = NULL;
    self->macro_expansion_limit = SPF_EVAL_POLICY_DEFAULT_MACRO_EXPANSION_LIMIT;
    self->max_dns_mech = SPF_EVAL_MAX_DNSMECH;
    self->max_label_len = SPF_EVAL_LABEL_MAX_LENGTH;
    self->max_mxrr_per_mxmech = SPF_EVAL_MAX_MXMECH_MXRR;
    self->max_ptrrr_per_ptrmech = SPF_EVAL_MAX_PTRMECH_PTRRR;
    self->void_lookup_limit = SPF_EVAL_VOID_LOOKUP_LIMIT;
    self->overwrite_all_directive_score = SPF_SCORE_NULL;
    self->action_on_plus_all_directive = SPF_CUSTOM_ACTION_NULL;
    self->action_on_malicious_ip4_cidr_length = SPF_CUSTOM_ACTION_NULL;
    self->malicious_ip4_cidr_length = 0;
    self->action_on_malicious_ip6_cidr_length = SPF_CUSTOM_ACTION_NULL;
    self->malicious_ip6_cidr_length = 0;
    return self;
}   // end function: SpfEvalPolicy_new

void
SpfEvalPolicy_setSpfRRLookup(SpfEvalPolicy *self, bool flag)
{
    self->lookup_spf_rr = flag;
}   // end function: SpfEvalPolicy_setSpfRRLookup

static SpfStat
SpfEvalPolicy_replaceString(const char *src, char **pdest)
{
    char *new = NULL;
    if (NULL != src && NULL == (new = strdup(src))) {
        return SPF_STAT_NO_RESOURCE;
    }   // end if
    free(*pdest);
    *pdest = new;
    return SPF_STAT_OK;
}   // end function: SpfEvalPolicy_replaceString

/**
 * %{r} macro of SPF record
 */
SpfStat
SpfEvalPolicy_setCheckingDomain(SpfEvalPolicy *self, const char *domain)
{
    return SpfEvalPolicy_replaceString(domain, &(self->checking_domain));
}   // end function: SpfEvalPolicy_setCheckingDomain

SpfStat
SpfEvalPolicy_setLocalPolicyDirectives(SpfEvalPolicy *self, const char *policy)
{
    return SpfEvalPolicy_replaceString(policy, &(self->local_policy));
}   // end function: SpfEvalPolicy_setLocalPolicyDirectives

SpfStat
SpfEvalPolicy_setLocalPolicyExplanation(SpfEvalPolicy *self, const char *explanation)
{
    return SpfEvalPolicy_replaceString(explanation, &(self->local_policy_explanation));
}   // end function: SpfEvalPolicy_setLocalPolicyExplanation

void
SpfEvalPolicy_setExplanationLookup(SpfEvalPolicy *self, bool flag)
{
    self->lookup_exp = flag;
}   // end function: SpfEvalPolicy_setExplanationLogging

void
SpfEvalPolicy_setPlusAllDirectiveHandling(SpfEvalPolicy *self, SpfCustomAction action)
{
    self->action_on_plus_all_directive = action;
}   // end function: SpfEvalPolicy_setPlusAllDirectiveHandling

void
SpfEvalPolicy_setVoidLookupLimit(SpfEvalPolicy *self, int void_lookup_limit)
{
    self->void_lookup_limit = void_lookup_limit;
}   // end function: SpfEvalPolicy_setVoidLookupLimit

/**
 * release SpfEvalPolicy object
 * @param self SpfEvalPolicy object to release
 */
void
SpfEvalPolicy_free(SpfEvalPolicy *self)
{
    if (NULL == self) {
        return;
    }   // end if

    free(self->checking_domain);
    free(self->local_policy);
    free(self->local_policy_explanation);
    free(self);
}   // end function: SpfEvalPolicy_free
