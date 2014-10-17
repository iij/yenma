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

#include <stddef.h>
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <libmilter/mfapi.h>

#include "ptrop.h"
#include "loghandler.h"
#include "refcountobj.h"
#include "ipaddrblocktree.h"
#include "resolverpool.h"
#include "spf.h"
#include "dkim.h"
#include "dmarc.h"
#include "authstats.h"
#include "yenmactrl.h"
#include "yenmacontext.h"

/*
 * @attention this function is thread-unsafe
 */
static void
YenmaContext_free(void *p)
{
    if (NULL == p) {
        return;
    }   // end if

    YenmaContext *self = (YenmaContext *) p;

    int ret = RefCountObj_FINI(self);
    if (0 != ret) {
        LogError("pthread_mutex_destroy failed: errno=%s", strerror(ret));
    }   // end if

    if (self->free_unreloadables) {
        YenmaCtrl_free(self->yenmactrl);
        AuthStatistics_free(self->stats);
        free(self->config_file);
    }   // end if

    ResolverPool_free(self->resolver_pool);
    IpAddrBlockTree_free(self->exclusion_block);
    DkimVerificationPolicy_free(self->dkim_vpolicy);
    SpfEvalPolicy_free(self->spfevalpolicy);
    SpfEvalPolicy_free(self->sidfevalpolicy);
    PublicSuffix_free(self->public_suffix);
    YenmaConfig_free(self->cfg);
    free(self);
}   // end function: YenmaContext_free

YenmaContext *
YenmaContext_new(void)
{
    YenmaContext *self = (YenmaContext *) malloc(sizeof(YenmaContext));
    if (NULL == self) {
        return NULL;
    }   // end if
    memset(self, 0, sizeof(YenmaContext));

    if (0 != RefCountObj_INIT(self)) {
        free(self);
        return NULL;
    }   // end if

    self->freefunc = YenmaContext_free;
    self->graceful_shutdown = false;
    self->free_unreloadables = true;

    return self;
}   // end function: YenmaContext_new

static inline bool
notstartwith(char *s, char c)
{
    return NULL != s && c != s[0];
}   // end function: notstartwith

/**
 * @attention this function may rewrite yenmacfg
 */
bool
YenmaContext_buildPolicies(YenmaContext *self, YenmaConfig *yenmacfg)
{
    // Resolver
    DnsResolver_initializer *initializer = DnsResolver_lookupInitializer(yenmacfg->resolver_engine);
    if (NULL == initializer) {
        LogError("failed to load resolver module: resolver=%s",
                 PTROR(yenmacfg->resolver_engine, "any"));
        return false;
    }   // end if
    self->resolver_pool =
        ResolverPool_new(initializer, yenmacfg->resolver_conf, yenmacfg->resolver_pool_size,
                         (int) yenmacfg->resolver_timeout, (int) yenmacfg->resolver_retry_count);
    if (NULL == self->resolver_pool) {
        LogNoResource();
        return false;
    }   // end if

    // DMARC setup
    if (yenmacfg->dmarc_verify) {
        // enable SPF and DKIM
        if (!yenmacfg->spf_verify) {
            yenmacfg->spf_verify = true;
            LogNotice("SPF verification is turned on as a part of DMARC verification");
        }   // end if
        if (!yenmacfg->dkim_verify) {
            yenmacfg->dkim_verify = true;
            LogNotice("DKIM verification is turned on as a part of DMARC verification");
        }   // end if

        // load public suffix list
        if (NULL == yenmacfg->dmarc_public_suffix_list) {
            LogError("Public Suffix List must be specified for DMARC verification");
            return false;
        }   // end if
        if (DSTAT_OK !=
            PublicSuffix_build(yenmacfg->dmarc_public_suffix_list, &self->public_suffix)) {
            LogError("failed to load public suffix list: filename=%s",
                     yenmacfg->dmarc_public_suffix_list);
            return false;
        }   // end if

        // check SMTP reject actions
        self->dmarc_reject_action = YenmaConfig_lookupSmtpRejectActionByKeyword(yenmacfg->dmarc_reject_action);
        if (0 > self->dmarc_reject_action) {
            LogError("invalid SMTP action for DMARC reject: action=%s", yenmacfg->dmarc_reject_action);
            return false;
        } else if (SMFIS_REJECT == self->dmarc_reject_action && (notstartwith(yenmacfg->dmarc_reject_reply_code, '5') || notstartwith(yenmacfg->dmarc_reject_enhanced_status_code, '5'))) {
            LogError("invalid SMTP reply code or enhanced status code  for DMARC reject action: reply_code=%s, ehanced_status_code=%s", NNSTR(yenmacfg->dmarc_reject_reply_code), NNSTR(yenmacfg->dmarc_reject_enhanced_status_code));
            return false;
        } else if (SMFIS_TEMPFAIL == self->dmarc_reject_action && (notstartwith(yenmacfg->dmarc_reject_reply_code, '4') || notstartwith(yenmacfg->dmarc_reject_enhanced_status_code, '4'))) {
            LogError("invalid SMTP reply code or enhanced status code  for DMARC tempfail action: reply_code=%s, ehanced_status_code=%s", NNSTR(yenmacfg->dmarc_reject_reply_code), NNSTR(yenmacfg->dmarc_reject_enhanced_status_code));
            return false;
        }   // end if
    }   // end if

    if (yenmacfg->dkim_adsp_verify && !yenmacfg->dkim_verify) {
        yenmacfg->dkim_verify = true;
        LogNotice("DKIM verification is turned on as a part of DKIM-ADSP verification");
    }   // end if

    // building DkimVerificationPolicy
    if (yenmacfg->dkim_verify) {
        DkimStatus config_stat =
            YenmaConfig_buildDkimVerificationPolicy(yenmacfg, &self->dkim_vpolicy);
        if (DSTAT_OK != config_stat) {
            return false;
        }   // end if
    }   // end if

    // building SpfEvalPolicy for SPF (must be after determining authserv-id)
    if (yenmacfg->spf_verify) {
        self->spfevalpolicy = YenmaConfig_buildSpfEvalPolicy(yenmacfg);
        if (NULL == self->spfevalpolicy) {
            return false;
        }   // end if
    }   // end if

    // building SpfEvalPolicy for SIDF (must be after determining authserv-id)
    if (yenmacfg->sidf_verify) {
        self->sidfevalpolicy = YenmaConfig_buildSidfEvalPolicy(yenmacfg);
        if (NULL == self->sidfevalpolicy) {
            return false;
        }   // end if
    }   // end if

    if (NULL != yenmacfg->service_exclusion_blocks) {
        self->exclusion_block = YenmaConfig_buildExclusionBlock(yenmacfg->service_exclusion_blocks);
        if (NULL == self->exclusion_block) {
            return false;
        }   // end if
    }   // end if

    return true;
}   // end function: YenmaContext_buildPolicies
