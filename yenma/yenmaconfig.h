/*
 * Copyright (c) 2008-2016 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifndef __YENMA_CONFIG_H__
#define __YENMA_CONFIG_H__

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <libmilter/mfapi.h>
#include "ipaddrblocktree.h"
#include "spf.h"
#include "dkim.h"
#include "configloader.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct YenmaConfig {
    ConfigStorageBase_MEMBER;
    char *service_chdir;
    char *service_pidfile;
    char *service_user;
    char *service_controlsocket;
    time_t service_graceful_shutdown_timeout;
    bool service_hold_tty_open;
    char *service_exclusion_blocks;
    int logging_facility;
    int logging_mask;
    char *logging_ident;
    char *milter_socket;
    int64_t milter_timeout;
    uint64_t milter_backlog;
    uint64_t milter_debuglevel;
    bool milter_lazy_qid_fetch;
// Resolver
    char *resolver_engine;
    char *resolver_conf;
    uint64_t resolver_pool_size;
    int64_t resolver_timeout;
    int64_t resolver_retry_count;
// Authentication-Results
    char *authresult_servid;
    bool authresult_use_spf_hardfail;
// SPF verification
    bool spf_verify;
    bool spf_lookup_spf_rr;
    bool spf_log_plus_all_directive;
    bool spf_append_explanation;
    int64_t spf_void_lookup_limit;
// Sender ID verification
    bool sidf_verify;
    bool sidf_lookup_spf_rr;
    bool sidf_log_plus_all_directive;
    bool sidf_append_explanation;
    int64_t sidf_void_lookup_limit;
// DKIM verification
    bool dkim_verify;
    bool dkim_accept_expired_signature;
    bool dkim_accept_future_signature;
    uint64_t dkim_signheader_limit;
    bool dkim_rfc4871_compatible;
    uint64_t dkim_min_rsa_key_length;
    time_t dkim_max_clock_skew;
    bool dkim_atps_verify;
    bool dkim_adsp_verify;
    char *dkim_canon_dump_dir;
// DMARC verification
    bool dmarc_verify;
    int vdmarc_verification;
    char *dmarc_public_suffix_list;
    char *dmarc_reject_action;
    char *dmarc_reject_reply_code;
    char *dmarc_reject_enhanced_status_code;
    char *dmarc_reject_message;
} YenmaConfig;

extern YenmaConfig *YenmaConfig_new(void);
extern void YenmaConfig_free(YenmaConfig *self);
extern bool YenmaConfig_load(YenmaConfig *self, const char *filename);
extern void YenmaConfig_dump(const YenmaConfig *self);
extern SpfEvalPolicy *YenmaConfig_buildSpfEvalPolicy(const YenmaConfig *self);
extern SpfEvalPolicy *YenmaConfig_buildSidfEvalPolicy(const YenmaConfig *self);
extern DkimStatus YenmaConfig_buildDkimVerificationPolicy(const YenmaConfig *self,
                                                          DkimVerificationPolicy **vpolicy);
extern IpAddrBlockTree *YenmaConfig_buildExclusionBlock(const char *exclusion_blocks);

extern sfsistat YenmaConfig_lookupSmtpRejectActionByKeyword(const char *action);
extern const char *YenmaConfig_lookupSmtpRejectActionByValue(sfsistat value);

#ifdef __cplusplus
}
#endif

#endif /* __YENMA_CONFIG_H__ */
