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

#ifndef __YENMA_CONTEXT_H__
#define __YENMA_CONTEXT_H__

#include <stdbool.h>

#include "refcountobj.h"
#include "ipaddrblocktree.h"
#include "dnsresolv.h"
#include "resolverpool.h"
#include "spf.h"
#include "dkim.h"
#include "dmarc.h"
#include "yenmaconfig.h"
#include "yenmactrl.h"
#include "authstats.h"

typedef struct YenmaContext {
    RefCountObj_MEMBER;
    bool free_unreloadables;    // flag whether or not to release unreloadable attributes
    // unreloadable attributes
    int argc;
    char **argv;
    char *config_file;
    YenmaCtrl *yenmactrl;
    volatile bool graceful_shutdown;
    AuthStatistics *stats;

    // reloadable attributes
    YenmaConfig *cfg;
    ResolverPool *resolver_pool;
    IpAddrBlockTree *exclusion_block;
    DkimVerificationPolicy *dkim_vpolicy;
    SpfEvalPolicy *spfevalpolicy;
    SpfEvalPolicy *sidfevalpolicy;
    PublicSuffix *public_suffix;
    sfsistat dmarc_reject_action;
} YenmaContext;

extern YenmaContext *YenmaContext_new(void);
#define YenmaContext_ref(_ctx) ((YenmaContext *) RefCountObj_ref((RefCountObj *) (_ctx)))
#define YenmaContext_unref(_ctx) RefCountObj_unref((RefCountObj *) (_ctx))
extern bool YenmaContext_buildPolicies(YenmaContext *self, YenmaConfig *yenmacfg);

#endif /* __YENMA_CONTEXT_H__ */
