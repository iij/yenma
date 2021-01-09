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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <libmilter/mfapi.h>

#include "ptrop.h"
#include "loghandler.h"
#include "keywordmap.h"
#include "configloader.h"
#include "socketaddress.h"
#include "ipaddrblocktree.h"
#include "spf.h"
#include "dkim.h"
#include "yenma.h"
#include "yenmaconfig.h"

#define EXCLUSION_BLOCK_DELIMITER " ,"

// *INDENT-OFF*

static const ConfigEntry yenma_config_table[] = {
    {"Service.Chdir", CONFIG_TYPE_STRING, NULL,
     offsetof(YenmaConfig, service_chdir), NULL},

    {"Service.PidFile", CONFIG_TYPE_STRING, "/var/run/" MILTERNAME ".pid",
     offsetof(YenmaConfig, service_pidfile), "pidfile"},

    {"Service.User", CONFIG_TYPE_STRING, NULL,
     offsetof(YenmaConfig, service_user), "user"},

    {"Service.ControlSocket", CONFIG_TYPE_STRING, NULL,
     offsetof(YenmaConfig, service_controlsocket), NULL},

    {"Service.GracefulShutdownTimeout", CONFIG_TYPE_TIME, "0",
     offsetof(YenmaConfig, service_graceful_shutdown_timeout), NULL},

    {"Service.HoldTtyOpen", CONFIG_TYPE_BOOLEAN, "false",
     offsetof(YenmaConfig, service_hold_tty_open), NULL},

    {"Service.ExclusionBlocks", CONFIG_TYPE_STRING, NULL,
     offsetof(YenmaConfig, service_exclusion_blocks), NULL},

    {"Logging.Facility", CONFIG_TYPE_SYSLOG_FACILITY, "mail",
     offsetof(YenmaConfig, logging_facility), NULL},

    {"Logging.Mask", CONFIG_TYPE_LOG_LEVEL, "info",
     offsetof(YenmaConfig, logging_mask), NULL},

    {"Logging.Ident", CONFIG_TYPE_STRING, MILTERNAME,
     offsetof(YenmaConfig, logging_ident), NULL},

    {"Milter.Socket", CONFIG_TYPE_STRING, "unix:/var/run/" MILTERNAME ".sock",
     offsetof(YenmaConfig, milter_socket), "milter socket"},

    {"Milter.Timeout", CONFIG_TYPE_INT64, "-1",
     offsetof(YenmaConfig, milter_timeout), NULL},

    {"Milter.Backlog", CONFIG_TYPE_UINT64, "100",
     offsetof(YenmaConfig, milter_backlog), "milter backlog"},

    {"Milter.DebugLevel", CONFIG_TYPE_UINT64, "0",
     offsetof(YenmaConfig, milter_debuglevel), NULL},

    {"Milter.LazyQidFetch", CONFIG_TYPE_BOOLEAN, "false",
     offsetof(YenmaConfig, milter_lazy_qid_fetch), "delay retrieving qid to support postfix"},

// Resolver
    {"Resolver.Engine", CONFIG_TYPE_STRING, NULL,
     offsetof(YenmaConfig, resolver_engine), NULL},

    {"Resolver.ConfigFile", CONFIG_TYPE_STRING, NULL,
     offsetof(YenmaConfig, resolver_conf), NULL},

    {"Resolver.PoolSize", CONFIG_TYPE_UINT64, "256",
     offsetof(YenmaConfig, resolver_pool_size), NULL},

    {"Resolver.Timeout", CONFIG_TYPE_INT64, "-1",
     offsetof(YenmaConfig, resolver_timeout), NULL},

    {"Resolver.RetryCount", CONFIG_TYPE_INT64, "-1",
     offsetof(YenmaConfig, resolver_retry_count), NULL},

// Authentication-Results
    {"AuthResult.ServId", CONFIG_TYPE_STRING, NULL,
     offsetof(YenmaConfig, authresult_servid), NULL},

    {"AuthResult.UseSpfHardfail", CONFIG_TYPE_BOOLEAN, "false",
     offsetof(YenmaConfig, authresult_use_spf_hardfail),
     "use spf \"hardfail\" result instead of \"fail\" to make compatible with RFC5451 (obsoleted)"},

// SPF verification
    {"SPF.Verify", CONFIG_TYPE_BOOLEAN, "true",
     offsetof(YenmaConfig, spf_verify), NULL},

    {"SPF.AppendExplanation", CONFIG_TYPE_BOOLEAN, "false",
     offsetof(YenmaConfig, spf_append_explanation), NULL},

    {"SPF.LookupSPFRR", CONFIG_TYPE_BOOLEAN, "false",
     offsetof(YenmaConfig, spf_lookup_spf_rr), NULL},

    {"SPF.LogPlusAllDirective", CONFIG_TYPE_BOOLEAN, "false",
     offsetof(YenmaConfig, spf_log_plus_all_directive), NULL},

    {"SPF.VoidLookupLimit", CONFIG_TYPE_INT64, "2",
     offsetof(YenmaConfig, spf_void_lookup_limit), NULL},

// Sender ID verification
    {"SIDF.Verify", CONFIG_TYPE_BOOLEAN, "false",
     offsetof(YenmaConfig, sidf_verify), NULL},

    {"SIDF.AppendExplanation", CONFIG_TYPE_BOOLEAN, "false",
     offsetof(YenmaConfig, sidf_append_explanation), NULL},

    {"SIDF.LookupSPFRR", CONFIG_TYPE_BOOLEAN, "false",
     offsetof(YenmaConfig, sidf_lookup_spf_rr), NULL},

    {"SIDF.LogPlusAllDirective", CONFIG_TYPE_BOOLEAN, "false",
     offsetof(YenmaConfig, sidf_log_plus_all_directive), NULL},

    {"SIDF.VoidLookupLimit", CONFIG_TYPE_INT64, "2",
     offsetof(YenmaConfig, sidf_void_lookup_limit), NULL},

// DKIM verification
    {"Dkim.Verify", CONFIG_TYPE_BOOLEAN, "true",
     offsetof(YenmaConfig, dkim_verify), NULL},

    {"Dkim.AcceptExpiredSignature", CONFIG_TYPE_BOOLEAN, "false",
     offsetof(YenmaConfig, dkim_accept_expired_signature), NULL},

    {"Dkim.AcceptFutureSignature", CONFIG_TYPE_BOOLEAN, "false",
     offsetof(YenmaConfig, dkim_accept_future_signature), NULL},

    {"Dkim.SignHeaderLimit", CONFIG_TYPE_UINT64, "3",
     offsetof(YenmaConfig, dkim_signheader_limit), NULL},

    {"Dkim.Rfc4871Compatible", CONFIG_TYPE_BOOLEAN, "false",
     offsetof(YenmaConfig, dkim_rfc4871_compatible), NULL},

    {"Dkim.MinRSAKeyLength", CONFIG_TYPE_UINT64, "0",
     offsetof(YenmaConfig, dkim_min_rsa_key_length), NULL},

    {"Dkim.MaxClockSkew", CONFIG_TYPE_TIME, "0",
     offsetof(YenmaConfig, dkim_max_clock_skew), NULL},

    {"DkimAtps.Verify", CONFIG_TYPE_BOOLEAN, "false",
     offsetof(YenmaConfig, dkim_atps_verify), NULL},

    {"DkimAdsp.Verify", CONFIG_TYPE_BOOLEAN, "false",
     offsetof(YenmaConfig, dkim_adsp_verify), NULL},

    {"Dkim.CanonDumpDir", CONFIG_TYPE_STRING, NULL,
     offsetof(YenmaConfig, dkim_canon_dump_dir), NULL},

// DMARC verification
    {"Dmarc.Verify", CONFIG_TYPE_BOOLEAN, "true",
     offsetof(YenmaConfig, dmarc_verify), NULL},

    {"Dmarc.VdmarcVerification", CONFIG_TYPE_VDMARC_VERIFICATION_MODE, "none",
     offsetof(YenmaConfig, vdmarc_verification), NULL},

    {"Dmarc.PublicSuffixList", CONFIG_TYPE_STRING, NULL,
     offsetof(YenmaConfig, dmarc_public_suffix_list), NULL},

    {"Dmarc.RejectAction", CONFIG_TYPE_STRING, "reject",
     offsetof(YenmaConfig, dmarc_reject_action), NULL},

    {"Dmarc.RejectReplyCode", CONFIG_TYPE_STRING, "550",
     offsetof(YenmaConfig, dmarc_reject_reply_code), NULL},

    {"Dmarc.RejectEnhancedStatusCode", CONFIG_TYPE_STRING, "5.7.1",
     offsetof(YenmaConfig, dmarc_reject_enhanced_status_code), NULL},

    {"Dmarc.RejectMessage", CONFIG_TYPE_STRING, "Email rejected per DMARC policy",
     offsetof(YenmaConfig, dmarc_reject_message), NULL},

    {NULL, CONFIG_TYPE_NULL, NULL, 0, NULL},   // sentinel
};
// *INDENT-ON*

#if defined(_POSIX_HOST_NAME_MAX)
#define AUTHHOSTNAMELEN _POSIX_HOST_NAME_MAX
#elif defined(MAXHOSTNAMELEN)
#define AUTHHOSTNAMELEN MAXHOSTNAMELEN
#else
#define AUTHHOSTNAMELEN 256
#endif

YenmaConfig *
YenmaConfig_new(void)
{
    YenmaConfig *self = (YenmaConfig *) malloc(sizeof(YenmaConfig));
    if (NULL == self) {
        return NULL;
    }   // end if
    memset(self, 0, sizeof(YenmaConfig));
    self->config_table = &yenma_config_table;

    return self;
}   // end function: YenmaConfig_new

void
YenmaConfig_free(YenmaConfig *self)
{
    if (NULL == self) {
        return;
    }   // end if
    ConfigLoader_cleanup((ConfigStorageBase *) self);
    free(self);
}   // end function: YenmaConfig_free

bool
YenmaConfig_load(YenmaConfig *self, const char *filename)
{
    assert(NULL != self);

    if (!ConfigLoader_load((ConfigStorageBase *) self, filename)) {
        return false;
    }   // end if
    ConfigLoader_applyDefaultValue((ConfigStorageBase *) self);

    // setup hostname (used as "authserv-id" of Authentication-Results: header)
    if (NULL == self->authresult_servid) {
        char tmphostname[AUTHHOSTNAMELEN];
        if (0 > gethostname(tmphostname, AUTHHOSTNAMELEN)) {
            LogError("hostname cannot determined: errno=%s", strerror(errno));
            return false;
        }   // end if
        if (NULL == (self->authresult_servid = strdup(tmphostname))) {
            LogNoResource();
            return false;
        }   // end if
        LogInfo("authserv-id is set to the hostname: authserv-id=%s", self->authresult_servid);
    }   // end if

    return true;
}   // end function: YenmaConfig_load

void
YenmaConfig_dump(const YenmaConfig *self)
{
    ConfigLoader_dump((ConfigStorageBase *) self);
}   // end function: YenmaConfig_dump

static SpfEvalPolicy *
YenmaConfig_buildSpfEvalPolicyImpl(const char *authresult_servid, bool lookup_spf_rr,
                                   bool log_plus_all_directive, bool lookup_explanation,
                                   int void_lookup_limit)
{
    SpfEvalPolicy *spfpolicy = SpfEvalPolicy_new();
    if (NULL == spfpolicy) {
        LogNoResource();
        return NULL;
    }   // end if
    if (SPF_STAT_OK != SpfEvalPolicy_setCheckingDomain(spfpolicy, authresult_servid)) {
        LogNoResource();
        return NULL;
    }   // end if
    SpfEvalPolicy_setSpfRRLookup(spfpolicy, lookup_spf_rr);
    SpfEvalPolicy_setPlusAllDirectiveHandling(spfpolicy,
                                              log_plus_all_directive ? SPF_CUSTOM_ACTION_LOGGING :
                                              SPF_CUSTOM_ACTION_NULL);
    SpfEvalPolicy_setVoidLookupLimit(spfpolicy, void_lookup_limit);
    SpfEvalPolicy_setExplanationLookup(spfpolicy, lookup_explanation);
    return spfpolicy;
}   // end function: YenmaConfig_buildSpfEvalPolicyImpl

SpfEvalPolicy *
YenmaConfig_buildSpfEvalPolicy(const YenmaConfig *self)
{
    return YenmaConfig_buildSpfEvalPolicyImpl(self->authresult_servid, self->spf_lookup_spf_rr,
                                              self->spf_log_plus_all_directive,
                                              self->spf_append_explanation,
                                              (int) self->spf_void_lookup_limit);
}   // end function: YenmaConfig_buildSpfEvalPolicy

SpfEvalPolicy *
YenmaConfig_buildSidfEvalPolicy(const YenmaConfig *self)
{
    return YenmaConfig_buildSpfEvalPolicyImpl(self->authresult_servid, self->sidf_lookup_spf_rr,
                                              self->sidf_log_plus_all_directive,
                                              self->sidf_append_explanation,
                                              (int) self->sidf_void_lookup_limit);
}   // end function: YenmaConfig_buildSidfEvalPolicy

DkimStatus
YenmaConfig_buildDkimVerificationPolicy(const YenmaConfig *self, DkimVerificationPolicy **vpolicy)
{
    assert(NULL != self);

    DkimVerificationPolicy *vpolicyobj = DkimVerificationPolicy_new();
    if (NULL == vpolicyobj) {
        LogNoResource();
        return DSTAT_SYSERR_NORESOURCE;
    }   // end if

    DkimVerificationPolicy_setSignHeaderLimit(vpolicyobj, self->dkim_signheader_limit);
    DkimVerificationPolicy_acceptExpiredSignature(vpolicyobj, self->dkim_accept_expired_signature);
    DkimVerificationPolicy_acceptFutureSignature(vpolicyobj, self->dkim_accept_future_signature);
    DkimVerificationPolicy_verifyAtpsDelegation(vpolicyobj, self->dkim_atps_verify);
    DkimVerificationPolicy_setRfc4871Compatible(vpolicyobj, self->dkim_rfc4871_compatible);
    DkimVerificationPolicy_setMinRSAKeyLength(vpolicyobj, (unsigned int) self->dkim_min_rsa_key_length);
    *vpolicy = vpolicyobj;
    return DSTAT_OK;
}   // end function: YenmaConfig_buildDkimVerificationPolicy

static const KeywordMap smtp_action_table[] = {
    {"none", SMFIS_CONTINUE},
    {"reject", SMFIS_REJECT},
    {"discard", SMFIS_DISCARD},
    {"tempfail", SMFIS_TEMPFAIL},
    {NULL, -1},
};

sfsistat
YenmaConfig_lookupSmtpRejectActionByKeyword(const char *keyword)
{
    return (sfsistat) KeywordMap_lookupByCaseString(smtp_action_table, keyword);
}   // end function: YenmaConfig_lookupSmtpRejectActionByKeyword

const char *
YenmaConfig_lookupSmtpRejectActionByValue(sfsistat value)
{
    return KeywordMap_lookupByValue(smtp_action_table, value);
}   // end function: YenmaConfig_lookupSmtpRejectActionByValue

static bool
YenmaConfig_buildExclusionBlockImpl(IpAddrBlockTree *blocks, const char *entry, size_t entrylen)
{
    struct sockaddr_storage sstart, send;
    socklen_t sstartlen = sizeof(sstart);
    socklen_t sendlen = sizeof(send);
    int gai_stat =
        SockAddr_parseIpAddrBlock(entry, entrylen, (struct sockaddr *) &sstart, &sstartlen,
                                  (struct sockaddr *) &send, &sendlen);
    if (0 != gai_stat) {
        int save_errno = errno;
        LogError("failed to parse exclusion block: entry=%.*s, error=%s", (int) entrylen, entry,
                 (EAI_SYSTEM != gai_stat) ? gai_strerror(gai_stat) : strerror(save_errno));
        return false;
    }   // end if
    if (!IpAddrBlockTree_insertBySockAddr
        (blocks, (struct sockaddr *) &sstart, (struct sockaddr *) &send, (void *) true)) {
        LogError("failed to register exclusion block: entry=%.*s, error=%s", (int) entrylen, entry,
                 strerror(errno));
        return false;
    }   // end if
    return true;
}   // end function: YenmaConfig_buildExclusionBlockImpl

IpAddrBlockTree *
YenmaConfig_buildExclusionBlock(const char *exclusion_blocks)
{
    IpAddrBlockTree *blocks = IpAddrBlockTree_new(NULL);
    if (NULL == blocks) {
        LogNoResource();
        return NULL;
    }   // end if

    const char *tail = STRTAIL(exclusion_blocks);
    for (const char *p = exclusion_blocks; p < tail;) {
        const char *entry_tail = strpbrk(p, EXCLUSION_BLOCK_DELIMITER);
        if (NULL == entry_tail) {   // final entry
            entry_tail = tail;
        }   // end if
        if (!YenmaConfig_buildExclusionBlockImpl(blocks, p, entry_tail - p)) {
            IpAddrBlockTree_free(blocks);
            return NULL;
        }   // end if
        p = entry_tail;
        // skip continuous delimiters
        for (; p < tail && NULL != strchr(EXCLUSION_BLOCK_DELIMITER, *p); ++p);
    }   // end for
    return blocks;
}   // end function: YenmaConfig_buildExclusionBlock
