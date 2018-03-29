/*
 * Copyright (c) 2008-2018 Internet Initiative Japan Inc. All rights reserved.
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

#include <sys/socket.h>
#include <sys/types.h>
#include <assert.h>
#include <limits.h>
#include <netdb.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <openssl/err.h>
#include <libmilter/mfapi.h>

#include "openssl_compat.h"
#include "ptrop.h"
#include "stdaux.h"
#include "loghandler.h"
#include "intarray.h"
#include "foldstring.h"
#include "validatedresult.h"
#include "authresult.h"
#include "xskip.h"
#include "socketaddress.h"
#include "milteraux.h"
#include "inetmailbox.h"
#include "resolverpool.h"
#include "spf.h"
#include "dkim.h"
#include "dmarc.h"
#include "yenmasession.h"
#include "yenma.h"

#define YENMA_MILTER_ACTION_FLAGS (SMFIF_ADDHDRS | SMFIF_CHGHDRS)

#define RESTORE_YENMASESSION(smfictx, psession) \
    do { \
        psession = (YenmaSession *) smfi_getpriv(smfictx); \
        if (NULL == psession) { \
            LogError("smfi_getpriv failed"); \
            return SMFIS_TEMPFAIL; \
        } \
    } while (0)

static int
yenma_insert_authenticationresults_header(SMFICTX *ctx, YenmaSession *session)
{
    const char *authheader_name = AuthResult_getFieldName();
    const char *authheader_body = AuthResult_getFieldBody(session->authresult);
    int insert_stat = smfi_insheader(ctx, 0, (char *) authheader_name, (char *) authheader_body);
    if (MI_SUCCESS != insert_stat) {
        LogError("smfi_insheader failed: %s", authheader_body);
        return insert_stat;
    }   // end if

    return MI_SUCCESS;
}   // end function: yenma_insert_authenticationresults_header

static int
yenma_invoke_actions(SMFICTX *ctx, YenmaSession *session, sfsistat *action)
{
    // inserting the Authentication-Results header
    int insert_stat = yenma_insert_authenticationresults_header(ctx, session);
    if (MI_SUCCESS != insert_stat) {
        return insert_stat;
    }   // end if

    // rejection (or other action) according to DMARC
    if (session->ctx->cfg->dmarc_verify && SMFIS_CONTINUE != session->ctx->dmarc_reject_action) {
        bool policy_reject = false;
        size_t alignernum = PtrArray_getCount(session->aligners);
        for (size_t i = 0; i < alignernum; ++i) {
            DmarcAligner *aligner = (DmarcAligner *) PtrArray_get(session->aligners, i);
            if (DMARC_RECEIVER_POLICY_REJECT == DmarcAligner_getReceiverPolicy(aligner, true)) {
                policy_reject = true;
                break;
            }   // end if
        }   // end for

        if (policy_reject) {
            LogInfo("DMARC reject action taken: action=%s",
                    YenmaConfig_lookupSmtpRejectActionByValue(session->ctx->dmarc_reject_action));
            if (SMFIS_REJECT == session->ctx->dmarc_reject_action ||
                SMFIS_TEMPFAIL == session->ctx->dmarc_reject_action) {
                if (MI_SUCCESS != smfi_setreply(ctx, session->ctx->cfg->dmarc_reject_reply_code,
                                                session->ctx->cfg->dmarc_reject_enhanced_status_code,
                                                session->ctx->cfg->dmarc_reject_message)) {
                    LogWarning("failed to set SMTP response: rcode=%s, xcode=%s, msg=%s",
                               NNSTR(session->ctx->cfg->dmarc_reject_reply_code),
                               NNSTR(session->ctx->cfg->dmarc_reject_enhanced_status_code),
                               NNSTR(session->ctx->cfg->dmarc_reject_message));
                }   // end if
            }   // end if
            *action = session->ctx->dmarc_reject_action;
        }   // end if
    }   // end if

    // other actions will be here...

    return MI_SUCCESS;
}   // end function: yenma_invoke_actions

static void
yenma_spfv_build_auth_result(const YenmaSession *session, SpfScore score, bool eval_by_sender)
{
    // 評価結果に応じたアクションの実行
    const char *spf_result_symbol =
        session->ctx->cfg->authresult_use_spf_hardfail
        ? SpfEnum_lookupClassicScoreByValue(score) : SpfEnum_lookupScoreByValue(score);
    assert(NULL != spf_result_symbol);

    // Authentication-Results ヘッダの生成
    (void) AuthResult_appendMethodSpec(session->authresult, AUTHRES_METHOD_SPF, spf_result_symbol);

    // 設定に応じて explanation を reasonspec に記述
    const char *explanation = SpfEvaluator_getExplanation(session->spfevaluator);
    if (session->ctx->cfg->spf_append_explanation && NULL != explanation) {
        AuthResult_appendReasonSpec(session->authresult, explanation);
    }   // end if

    // propspec
    if (eval_by_sender) {   // EnvFrom で評価した場合
        (void) AuthResult_appendPropSpecWithAddrSpec(session->authresult, AUTHRES_PTYPE_SMTP,
                                                     AUTHRES_PROPERTY_MAILFROM, session->envfrom);
    } else {    // HELO で評価した場合
        (void) AuthResult_appendPropSpecWithToken(session->authresult, AUTHRES_PTYPE_SMTP,
                                                  AUTHRES_PROPERTY_HELO, session->helohost);
    }   // end if

    // SPF 検証結果をログに残す
    LogEvent("SPF-verify", "spf=%s, ipaddr=%s, eval=smtp.%s, helo=%s, envfrom=%s",
             spf_result_symbol, session->ipaddr,
             eval_by_sender ? AUTHRES_PROPERTY_MAILFROM : AUTHRES_PROPERTY_HELO,
             NNSTR(session->helohost), NNSTR(session->raw_envfrom));
}   // end function: yenma_spfv_build_auth_result

static void
yenma_sidfv_build_auth_result(const YenmaSession *session, const char *pra_header,
                              const InetMailbox *pra_mailbox, SpfScore score)
{
    // 評価結果に応じたアクションの実行
    const char *sidf_result_symbol =
        session->ctx->cfg->authresult_use_spf_hardfail
        ? SpfEnum_lookupClassicScoreByValue(score) : SpfEnum_lookupScoreByValue(score);
    assert(NULL != sidf_result_symbol);

    // Authentication-Results ヘッダの生成
    (void) AuthResult_appendMethodSpec(session->authresult, AUTHRES_METHOD_SENDERID,
                                       sidf_result_symbol);

    // 設定に応じて explanation を reasonspec に記述
    const char *explanation = SpfEvaluator_getExplanation(session->sidfevaluator);
    if (session->ctx->cfg->sidf_append_explanation && NULL != explanation) {
        AuthResult_appendReasonSpec(session->authresult, explanation);
    }   // end if

    // propspec
    (void) AuthResult_appendPropSpecWithAddrSpec(session->authresult, AUTHRES_PTYPE_HEADER,
                                                 pra_header, pra_mailbox);

    // SIDF 検証結果をログに残す
    LogEvent("SIDF-verify", "sender-id=%s, ipaddr=%s, header.%s=%s@%s", sidf_result_symbol,
             session->ipaddr, pra_header, InetMailbox_getLocalPart(pra_mailbox),
             InetMailbox_getDomain(pra_mailbox));
}   // end function: yenma_sidfv_build_auth_result

/**
 * DKIM verification and Authentication-Results header insertion
 * @param session session context
 * @return true on success, false on error.
 */
static bool
yenma_dkimv_eom(YenmaSession *session)
{
    DkimStatus verify_stat = DkimVerifier_verify(session->verifier);
    if (DSTAT_ISCRITERR(verify_stat)) {
        LogError("DkimVerifier_verify failed: error=%s", DkimStatus_getSymbol(verify_stat));
        return false;
    } else if (DSTAT_OK == verify_stat) {
        size_t signum = DkimVerifier_getFrameCount(session->verifier);
        for (size_t sigidx = 0; sigidx < signum; ++sigidx) {
            const DkimFrameResult *result = DkimVerifier_getFrameResult(session->verifier, sigidx);
            if (0 == sigidx) {
                // Most of messages have only one DKIM signature at most.
                // So we count the first DKIM verification result only here.
                session->validated_result->dkim_score = result->score;
            }   // end if

            const char *dkim_score_symbol = DkimEnum_lookupScoreByValue(result->score);
            (void) AuthResult_appendMethodSpec(session->authresult, AUTHRES_METHOD_DKIM,
                                               dkim_score_symbol);

            // append the cause of the verification failure
            if (DKIM_BASE_SCORE_NONE != result->score && DKIM_BASE_SCORE_PASS != result->score) {
                const char *reason = DkimStatus_strerror(result->stauts);
                if (NULL != reason) {
                    AuthResult_appendReasonSpec(session->authresult, reason);
                }   // end if
            }   // end if

            // display a testing flag as a comment
            if (result->testing) {
                (void) AuthResult_appendComment(session->authresult, AUTHRES_COMMENT_TESTING);
            }   // end if

            if (NULL != result->auid) {
                session->validated_result->dkim_eval_address = InetMailbox_duplicate(result->auid); // save AUID

                (void) AuthResult_appendPropSpecWithAddrSpec(session->authresult,
                                                             AUTHRES_PTYPE_HEADER,
                                                             AUTHRES_PROPERTY_I, result->auid);
                LogEvent("DKIM",
                         AUTHRES_METHOD_DKIM "=%s, status=%s, pkey=%dbits, testing=%s, "
                         AUTHRES_PTYPE_HEADER "." AUTHRES_PROPERTY_I "=%s@%s", dkim_score_symbol,
                         DkimStatus_getSymbol(result->stauts), result->pkey_bits,
                         result->testing ? "true" : "false", InetMailbox_getLocalPart(result->auid),
                         InetMailbox_getDomain(result->auid));
            } else {
                LogEvent("DKIM", AUTHRES_METHOD_DKIM "=%s, status=%s, pkey=%dbits, testing=%s",
                         dkim_score_symbol, DkimStatus_getSymbol(result->stauts), result->pkey_bits,
                         result->testing ? "true" : "false");
            }   // end if
        }   // end for
    } else {
        // DKIM 検証プロセス全体のエラー
        session->validated_result->dkim_score = DkimVerifier_getSessionResult(session->verifier);
        assert(DKIM_BASE_SCORE_NULL != session->validated_result->dkim_score);
        const char *dkim_score_symbol =
            DkimEnum_lookupScoreByValue(session->validated_result->dkim_score);
        (void) AuthResult_appendMethodSpec(session->authresult, AUTHRES_METHOD_DKIM,
                                           dkim_score_symbol);
        LogEvent("DKIM", AUTHRES_METHOD_DKIM "=%s", dkim_score_symbol);
    }   // end if

    if (session->ctx->cfg->dkim_adsp_verify) {
        DkimStatus policy_stat = DkimVerifier_checkAuthorPolicy(session->verifier);
        if (DSTAT_OK != policy_stat) {
            LogError("DkimVerifier_checkAuthorPolicy failed: error=%s",
                     DkimStatus_getSymbol(policy_stat));
            return false;
        }   // end if

        size_t signum = DkimVerifier_getPolicyFrameCount(session->verifier);
        for (size_t i = 0; i < signum; ++i) {
            const InetMailbox *author;
            DkimAdspScore adsp_score;
            DkimAtpsScore atps_score;
            if (!DkimVerifier_getPolicyFrameResult
                (session->verifier, i, &author, &adsp_score, &atps_score)) {
                // must not reach here
                continue;
            }   // end if

            if (0 == i) {
                // Most of messages have only one mailbox in the From header.
                // So we count the first DKIM ADSP score only here.
                session->validated_result->dkim_adsp_score = adsp_score;
            }   // end if

            // ADSP
            if (DKIM_ADSP_SCORE_NULL != adsp_score) {
                const char *adsp_score_symbol = DkimEnum_lookupAdspScoreByValue(adsp_score);
                (void) AuthResult_appendMethodSpec(session->authresult, AUTHRES_METHOD_DKIMADSP,
                                                   adsp_score_symbol);
                if (NULL != author) {
                    (void) AuthResult_appendPropSpecWithAddrSpec(session->authresult,
                                                                 AUTHRES_PTYPE_HEADER,
                                                                 AUTHRES_PROPERTY_FROM, author);
                    LogEvent("DKIM-ADSP",
                             AUTHRES_METHOD_DKIMADSP "=%s, " AUTHRES_PTYPE_HEADER "."
                             AUTHRES_PROPERTY_FROM "=%s@%s", adsp_score_symbol,
                             InetMailbox_getLocalPart(author), InetMailbox_getDomain(author));
                } else {
                    LogEvent("DKIM-ADSP", AUTHRES_METHOD_DKIMADSP "=%s", adsp_score_symbol);
                }   // end if
            }   // end if

            // ATPS
            if (DKIM_ATPS_SCORE_NULL != atps_score) {
                const char *atps_score_symbol = DkimEnum_lookupAtpsScoreByValue(atps_score);
                (void) AuthResult_appendMethodSpec(session->authresult, AUTHRES_METHOD_DKIMATPS,
                                                   atps_score_symbol);
                if (NULL != author) {
                    (void) AuthResult_appendPropSpecWithAddrSpec(session->authresult,
                                                                 AUTHRES_PTYPE_HEADER,
                                                                 AUTHRES_PROPERTY_FROM, author);
                    LogEvent("DKIM-ATPS",
                             AUTHRES_METHOD_DKIMATPS "=%s, " AUTHRES_PTYPE_HEADER "."
                             AUTHRES_PROPERTY_FROM "=%s@%s", atps_score_symbol,
                             InetMailbox_getLocalPart(author), InetMailbox_getDomain(author));
                } else {
                    LogEvent("DKIM-ATPS", AUTHRES_METHOD_DKIMATPS "=%s", atps_score_symbol);
                }   // end if
            }   // end if
        }   // end for
    }   // end if

    return true;
}   // end function: yenma_dkimv_eom

/**
 * @param ready SPF の検証が続行可能かを受け取る変数へのポインタ.
 *        SPF の検証を続行可能な場合は true,
 *        SPF の検証をおこなうのに十分な情報が揃わなかった場合は false.
 * @return true on success, false on error.
 */
static bool
yenma_spfv_prepare_request(YenmaSession *session, SpfEvaluator *evaluator, bool *spfready)
{
    // パラメーターのセット
    if (!SpfEvaluator_setIpAddr(evaluator, session->hostaddr->sa_family, session->hostaddr)) {
        LogError("SpfEvaluator_setIpAddr failed, invalid address family: sa_family=0x%x",
                 session->hostaddr->sa_family);
        return false;
    }   // end if

    if (NULL != session->envfrom && !InetMailbox_isNullAddr(session->envfrom)) {
        if (!SpfEvaluator_setSender(evaluator, session->envfrom)) {
            LogNoResource();
            return false;
        }   // end if
        LogDebug("SPF-EnvFrom-Domain=%s", InetMailbox_getDomain(session->envfrom));
    }   // end if

    // %{h} マクロの展開に使われる可能性があるので, HELO の値は必ずセットする.
    // Sender がセットされていれば HELO で SPF/SIDF の評価がおこなわれることはない.
    if (NULL == session->helohost) {
        LogEvent("SPF-skip", "HELO is not set, SPF-verification is skipped: ipaddr=%s",
                 session->ipaddr);
        *spfready = false;
        return true;
    }   // end if

    if (NULL == SpfEvaluator_getSender(evaluator)) {
        // EnvFrom が空なので HELO をSPFの評価対象にする場合
        // 2821-Domain or 2821-sub-domain にマッチするか確認, address-literal も除外する
        const char *p = session->helohost;
        if (0 >= XSkip_realDomain(p, STRTAIL(p), &p) || '\0' != *p) {
            LogEvent("SPF-skip",
                     "HELO doesn't seem to be 2821-Domain, SPF-verification is skipped: ipaddr=%s, helo=%s",
                     session->ipaddr, session->helohost);
            *spfready = false;
            return true;
        }   // end if
        LogDebug("SPF-HELO-Domain=%s", session->helohost);
    }   // end if

    if (!SpfEvaluator_setHeloDomain(evaluator, session->helohost)) {
        LogError("SpfEvaluator_setHeloDomain failed: helo=%s", session->helohost);
        return false;
    }   // end if

    *spfready = true;
    return true;
}   // end function: yenma_spfv_prepare_request

/**
 * SPF evaluation and Authentication-Results header insertion
 * @param session session context
 * @return true on success, false on error.
 */
static bool
yenma_spfv_eom(YenmaSession *session)
{
    if (NULL == session->spfevaluator) {
        session->spfevaluator = SpfEvaluator_new(session->ctx->spfevalpolicy, session->resolver);
        if (NULL == session->spfevaluator) {
            LogNoResource();
            return false;
        }   // end if
    } else {
        SpfEvaluator_reset(session->spfevaluator);
    }   // end if

    bool spfready;
    if (!yenma_spfv_prepare_request(session, session->spfevaluator, &spfready)) {
        return false;
    }   // end if

    if (spfready) {
        // SPF 評価の実行
        SpfScore score = SpfEvaluator_eval(session->spfevaluator, SPF_RECORD_SCOPE_SPF1);
        session->validated_result->spf_score = score;
        if (SPF_SCORE_SYSERROR == score || SPF_SCORE_NULL == score) {
            LogWarning("SpfEvaluator_eval failed: spf=0x%x", score);
            return false;
        }   // end if
        bool isSenderContext = SpfEvaluator_isSenderContext(session->spfevaluator);
        // 検証した値に応じて、SPF の検証結果を記憶
        session->validated_result->spf_eval_by_sender = isSenderContext;
        if (isSenderContext) {
            session->validated_result->spf_eval_address.envfrom = InetMailbox_duplicate(session->envfrom);  // envfrom で検証
        } else {
            session->validated_result->spf_eval_address.helohost = strdup(session->helohost);   // helo で検証
        }   // end if

        // Authentication-Results ヘッダの挿入
        yenma_spfv_build_auth_result(session, score, isSenderContext);
    } else {
        // 必要なパラメーターが揃わず SPF 評価をスキップした場合は "permerror"
        /*
         * [RFC7208] 2.6.7.
         * A "permerror" result means the domain's published records could not
         * be correctly interpreted.  This signals an error condition that
         * definitely requires DNS operator intervention to be resolved.
         */
        session->validated_result->spf_score = SPF_SCORE_PERMERROR;
        const char *spfresultexp = SpfEnum_lookupScoreByValue(session->validated_result->spf_score);
        (void) AuthResult_appendMethodSpec(session->authresult, AUTHRES_METHOD_SPF, spfresultexp);
        LogEvent("SPF-verify", "spf=%s", spfresultexp);
    }   // end if

    return true;
}   // end function: yenma_spfv_eom

/**
 * @param ready SPF の検証が続行可能かを受け取る変数へのポインタ.
 *        返値が true だった場合のみセットされる.
 *        SPF の検証を続行可能な場合は true,
 *        SPF の検証をおこなうのに十分な情報が揃わなかった場合は false.
 * @return true on success, false on error.
 */
static bool
yenma_sidfv_prepare_request(YenmaSession *session, SpfEvaluator *evaluator, bool *sidfready,
                            const char **pra_header, InetMailbox **pra_mailbox)
// XXX SPF との共通部分を取り出す
{
    // %{h} マクロの展開に使われる可能性があるので, HELO の値は必ずセットする.
    // Sender がセットされていれば HELO で SPF/SIDF の評価がおこなわれることはない.
    if (NULL == session->helohost) {
        LogEvent("SIDF-skip", "HELO is not set, SIDF-verification is skipped: ipaddr=%s",
                 session->ipaddr);
        *sidfready = false;
        return true;
    }   // end if

    if (!SpfEvaluator_setHeloDomain(evaluator, session->helohost)) {
        LogError("SpfEvaluator_setHeloDomain failed: helo=%s", session->helohost);
        return false;
    }   // end if

    // パラメーターのセット
    if (!SpfEvaluator_setIpAddr(evaluator, session->hostaddr->sa_family, session->hostaddr)) {
        LogError("SpfEvaluator_setIpAddr failed, invalid address family: sa_family=0x%x",
                 session->hostaddr->sa_family);
        return false;
    }   // end if

    // PRA ヘッダの抽出
    int pra_index;
    if (!SidfPra_extract(session->headers, &pra_index, pra_mailbox)) {
        return false;
    }   // end if
    if (NULL == *pra_mailbox) {
        LogEvent("SIDF-skip", "PRA header extraction failed");
        *sidfready = false;
        return true;
    }   // end if

    InetMailHeaders_get(session->headers, pra_index, pra_header, NULL);
    LogDebug("SIDF-PRA-Header: field=%s, mailbox=%s@%s", *pra_header,
             InetMailbox_getLocalPart(*pra_mailbox), InetMailbox_getDomain(*pra_mailbox));

    if (!SpfEvaluator_setSender(evaluator, *pra_mailbox)) {
        LogNoResource();
        InetMailbox_free(*pra_mailbox);
        *pra_mailbox = NULL;
        return false;
    }   // end if

    *sidfready = true;
    return true;
}   // end function: yenma_sidfv_prepare_request

/**
 * SenderID evaluation and Authentication-Results header insertion
 * @param session session context
 * @return true on success, false on error.
 */
static bool
yenma_sidfv_eom(YenmaSession *session)
{
    if (NULL == session->sidfevaluator) {
        session->sidfevaluator = SpfEvaluator_new(session->ctx->sidfevalpolicy, session->resolver);
        if (NULL == session->sidfevaluator) {
            LogNoResource();
            return false;
        }   // end if
    } else {
        SpfEvaluator_reset(session->sidfevaluator);
    }   // end if

    bool sidfready;
    const char *pra_header = NULL;
    InetMailbox *pra_mailbox = NULL;
    if (!yenma_sidfv_prepare_request
        (session, session->sidfevaluator, &sidfready, &pra_header, &pra_mailbox)) {
        return false;
    }   // end if

    if (sidfready) {
        // SIDF 評価の実行
        SpfScore score = SpfEvaluator_eval(session->sidfevaluator, SPF_RECORD_SCOPE_SPF2_PRA);
        session->validated_result->sidf_score = score;
        if (SPF_SCORE_SYSERROR == score || SPF_SCORE_NULL == score) {
            LogWarning("SpfEvaluator_eval failed: sender-id=0x%x", score);
            return false;
        }   // end if
        // Authentication-Results ヘッダの挿入
        yenma_sidfv_build_auth_result(session, pra_header, pra_mailbox, score);
        InetMailbox_free(pra_mailbox);
    } else {
        // 必要なパラメーターが揃わず SIDF 評価をスキップした場合は "permerror"
        /*
         * [RFC7208] 2.6.7.
         * A "permerror" result means the domain's published records could not
         * be correctly interpreted.  This signals an error condition that
         * definitely requires DNS operator intervention to be resolved.
         */
        session->validated_result->sidf_score = SPF_SCORE_PERMERROR;
        const char *sidfresultexp =
            SpfEnum_lookupScoreByValue(session->validated_result->sidf_score);
        (void) AuthResult_appendMethodSpec(session->authresult, AUTHRES_METHOD_SENDERID,
                                           sidfresultexp);
        LogEvent("SIDF-verify", "sender-id=%s", sidfresultexp);
    }   // end if

    return true;
}   // end function: yenma_sidfv_eom

static bool
yenma_dmarcv_eom(YenmaSession *session)
{
    /*
     * [RFC7489] 6.6.1.
     * The case of a syntactically valid multi-valued RFC5322.From field
     * presents a particular challenge.  The process in this case is to
     * apply the DMARC check using each of those domains found in the
     * RFC5322.From field as the Author Domain and apply the most strict
     * policy selected among the checks that fail.
     */

    // We evaluate DMARC policy against all of the header-From addresses
    // and apply the most strict policy.
    session->aligners = PtrArray_new(0, (void (*)(void *)) DmarcAligner_free);

    bool author_found = false;
    int headernum = InetMailHeaders_getCount(session->headers);
    for (int i = 0; i < headernum; ++i) {
        const char *headerf, *headerv;
        InetMailHeaders_get(session->headers, i, &headerf, &headerv);
        if (0 != strcasecmp(headerf, FROMHEADER)) {
            continue;
        }   // end if
        const char *errptr = NULL;
        InetMailboxArray *authors =
            InetMailHeaders_parseMailboxList(headerv, STRTAIL(headerv), &errptr);
        if (NULL == authors) {
            if (NULL == errptr) {
                LogNoResource();
                return false;
            } else {
                // parse error
                continue;
            }   // end if
        }   // end if
        int authornum = InetMailboxArray_getCount(authors);
        for (int j = 0; j < authornum; ++j) {
            const InetMailbox *author = InetMailboxArray_get(authors, j);
            DmarcAligner *aligner = NULL;
            DkimStatus dmarc_stat =
                DmarcAligner_new(session->ctx->public_suffix, session->resolver, &aligner);
            if (DSTAT_OK != dmarc_stat) {
                LogNoResource();
                return false;
            }   // end if
            if (0 > PtrArray_append(session->aligners, aligner)) {
                DmarcAligner_free(aligner);
                LogNoResource();
                return false;
            }   // end if
            DmarcScore score =
                DmarcAligner_check(aligner, author, session->verifier, session->spfevaluator);
            if (DMARC_SCORE_NULL == score) {
                LogWarning("DmarcAligner_check failed");
                return false;
            }   // end if
            const char *score_symbol = DmarcEnum_lookupScoreByValue(score);
            (void) AuthResult_appendMethodSpec(session->authresult, AUTHRES_METHOD_DMARC,
                                               score_symbol);
            (void) AuthResult_appendPropSpecWithAddrSpec(session->authresult, AUTHRES_PTYPE_HEADER,
                                                         AUTHRES_PROPERTY_FROM, author);
            LogEvent("DMARC",
                     AUTHRES_METHOD_DMARC "=%s, " AUTHRES_PTYPE_HEADER "." AUTHRES_PROPERTY_FROM
                     "=%s@%s", score_symbol, InetMailbox_getLocalPart(author),
                     InetMailbox_getDomain(author));

            if (!author_found) {
                session->validated_result->dmarc_score = score;
                author_found = true;
            }   // end if
        }   // end for
    }   // end for

    if (!author_found) {
        (void) AuthResult_appendMethodSpec(session->authresult, AUTHRES_METHOD_DMARC, "none");
        session->validated_result->dmarc_score = DMARC_SCORE_NONE;
    }   // end if

    return true;
}   // end function: yenma_dmarcv_eom

static const char *
yenma_set_qid(SMFICTX *ctx, YenmaSession *session)
{
    char *qid = smfi_getsymval(ctx, "i");
    if (NULL == qid || NULL == (session->qid = strdup(qid))) {
        LogWarning("failed to get qid");
        session->qid = strdup(NOQID);
    }   // end if
    (void) LogHandler_setPrefix(qid);
    return session->qid;
}   // end function: yenma_set_qid

static bool
yenma_setup_session(YenmaSession *session, _SOCK_ADDR *hostaddr)
{
    // [SPF] Storing the source IP address
    if (NULL == hostaddr) {
        LogError("milter host address is NULL");
        return false;
    }   // end if
    free(session->hostaddr);
    session->hostaddr = milter_dupaddr(hostaddr);
    if (NULL == session->hostaddr) {
        LogError("milter socket address duplication failed: errno=%s", strerror(errno));
        return false;
    }   // end if

    socklen_t socklen =
        (AF_INET == hostaddr->sa_family) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
    int gai_stat = SockAddr_getNumericNameInfo(session->hostaddr, &socklen, true, session->ipaddr,
                                               sizeof(session->ipaddr));
    if (0 != gai_stat) {
        int save_errno = errno;
        LogWarning("failed to format the source ip address: error=%s",
                   (EAI_SYSTEM != gai_stat) ? gai_strerror(gai_stat) : strerror(save_errno));
        snprintf(session->ipaddr, sizeof(session->ipaddr), "(unavailable)");
    }   // end if

    if (NULL == session->resolver) {
        session->resolver = ResolverPool_acquire(session->ctx->resolver_pool);
        if (NULL == session->resolver) {
            LogError("failed to initialize DNS resolver: resolver=%s, conf=%s",
                     NNSTR(session->ctx->cfg->resolver_engine),
                     NNSTR(session->ctx->cfg->resolver_conf));
            return false;
        }   // end if
    }   // end if

    return true;
}   // end function: yenma_setup_session

/**
 * clean-up when the SMTP transaction has been cancelled
 */
static sfsistat
yenma_tempfail(YenmaSession *session)
{
    YenmaSession_reset(session);
    (void) LogHandler_setPrefix(NULL);
    return SMFIS_TEMPFAIL;
}   // end function: yenma_tempfail

YenmaContext *
yenma_get_context_reference(void)
{
    int ret = pthread_rwlock_timedrdlock(&g_yenma_ctx_lock, &g_yenma_ctx_lock_timeout);
    if (0 != ret) {
        LogError("pthread_rwlock_timedrdlock failed: errno=%s", strerror(ret));
        return NULL;
    }   // end if

    YenmaContext *ctxref = YenmaContext_ref(g_yenma_ctx);

    ret = pthread_rwlock_unlock(&g_yenma_ctx_lock);
    if (0 != ret) {
        LogError("pthread_rwlock_unlock failed: errno=%s", strerror(ret));
    }   // end if

    if (NULL == ctxref) {
        LogError("YenmaContext unavailable");
        return NULL;
    }   // end if

    return ctxref;
}   // end function: yenma_get_context_reference

/* ----- ----- milter callback functions ----- ----- */

#if defined(HAVE_MILTER_XXFI_NEGOTIATE)
static sfsistat
yenmamfi_negotiate(SMFICTX *ctx, unsigned long f0 __attribute__((unused)),
                   unsigned long f1, unsigned long f2 __attribute__((unused)),
                   unsigned long f3 __attribute__((unused)), unsigned long *pf0,
                   unsigned long *pf1, unsigned long *pf2, unsigned long *pf3)
{
    LogDebug("%s called: SMFIP_HDR_LEADSPC=%s", __func__,
             (f1 & SMFIP_HDR_LEADSPC) ? "true" : "false");

    int counter_stat = AtomicCounter_increment(g_yenma_conn_counter);
    if (0 != counter_stat) {
        // This error only affects graceful shutdown function. So no need to abort.
        LogWarning("failed to increment milter connection counter: errno=%s",
                   strerror(counter_stat));
    }   // end if

    YenmaContext *ctxref = yenma_get_context_reference();
    if (NULL == ctxref) {
        goto cleanup;
    }   // end if

    YenmaSession *session = YenmaSession_new(ctxref);
    if (NULL == session) {
        LogError("YenmaSession_new failed: errno=%s", strerror(errno));
        YenmaContext_unref(ctxref);
        goto cleanup;
    }   // end if

    *pf0 = YENMA_MILTER_ACTION_FLAGS;
    *pf1 = SMFIP_NORCPT | SMFIP_NOUNKNOWN | SMFIP_NODATA;
    if (f1 & SMFIP_HDR_LEADSPC) {
        *pf1 |= SMFIP_HDR_LEADSPC;
        session->keep_leading_header_space = true;
    }   // end if

    // The (output) parameters pf2 and pf3 should be set to 0 for compatibility with future versions.
    *pf2 = 0;
    *pf3 = 0;

    if (MI_FAILURE == smfi_setpriv(ctx, session)) {
        YenmaSession_free(session);
        LogError("smfi_setpriv failed");
        goto cleanup;
    }   // end if

    return SMFIS_CONTINUE;

  cleanup:
    (void) AtomicCounter_decrement(g_yenma_conn_counter);
    return SMFIS_TEMPFAIL;
}   // end function: yenmamfi_negotiate
#endif

static sfsistat
yenmamfi_connect_action(YenmaSession *session, _SOCK_ADDR *hostaddr)
{
    if (NULL != session->ctx->exclusion_block && NULL != hostaddr
        && NULL != IpAddrBlockTree_lookupBySockAddr(session->ctx->exclusion_block, hostaddr)) {
        return SMFIS_ACCEPT;
    }   // end if

    return yenma_setup_session(session, hostaddr) ? SMFIS_CONTINUE : SMFIS_TEMPFAIL;
}   // end function: yenmamfi_connect_action

/**
 * Handle the SMTP connection.
 * @param ctx the opaque context structure.
 * @param hostname the host name of the message sender, as determined
 *        by a reverse lookup on the host address. If the reverse lookup
 *        fails, hostname will contain the message sender's IP address
 *        enclosed in square brackets (e.g. `[a.b.c.d]').
 * @param hostaddr the host address, as determined by a getpeername()
 *        call on the SMTP socket. NULL if the type is not supported
 *        in the current version or if the SMTP connection is made via stdin.
 */
static sfsistat
yenmamfi_connect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *hostaddr)
{
    LogDebug("%s called: revhostname=%s", __func__, NNSTR(hostname));

    YenmaSession *session = (YenmaSession *) smfi_getpriv(ctx);
    if (NULL != session) {  // switch if YenmaSession is already allocated in yenmamfi_negotiate
        return yenmamfi_connect_action(session, hostaddr);
    }   // end if

    int counter_stat = AtomicCounter_increment(g_yenma_conn_counter);
    if (0 != counter_stat) {
        // This error only affects graceful shutdown function. So no need to abort.
        LogWarning("failed to increment milter connection counter: errno=%s",
                   strerror(counter_stat));
    }   // end if

    YenmaContext *ctxref = yenma_get_context_reference();
    if (NULL == ctxref) {
        goto cleanup;
    }   // end if

    if (NULL != ctxref->exclusion_block && NULL != hostaddr
        && NULL != IpAddrBlockTree_lookupBySockAddr(ctxref->exclusion_block, hostaddr)) {
        YenmaContext_unref(ctxref);
        (void) AtomicCounter_decrement(g_yenma_conn_counter);
        return SMFIS_ACCEPT;
    }   // end if

    session = YenmaSession_new(ctxref);
    if (NULL == session) {
        LogError("YenmaSession_new failed: errno=%s", strerror(errno));
        YenmaContext_unref(ctxref);
        goto cleanup;
    }   // end if

    if (!yenma_setup_session(session, hostaddr)) {
        YenmaSession_free(session);
        goto cleanup;
    }   // end if

    if (MI_FAILURE == smfi_setpriv(ctx, session)) {
        YenmaSession_free(session);
        LogError("smfi_setpriv failed");
        goto cleanup;
    }   // end if

    return SMFIS_CONTINUE;

  cleanup:
    (void) AtomicCounter_decrement(g_yenma_conn_counter);
    return SMFIS_TEMPFAIL;
}   // end function: yenmamfi_connect

/**
 * Handle the HELO/EHLO command.
 * @param ctx Opaque context structure.
 * @param helohost Value passed to HELO/EHLO command, which should be
 *                 the domain name of the sending host (but is, in practice,
 *                 anything the sending host wants to send).
 */
static sfsistat
yenmamfi_helo(SMFICTX *ctx, char *helohost)
{
    LogDebug("%s called: helo=%s", __func__, NNSTR(helohost));

    YenmaSession *session = NULL;
    RESTORE_YENMASESSION(ctx, session);

    // [SPF] Storing the HELO/EHLO parameter
    // HELO を1コネクション中に複数回受け付けてしまうのでその対策
    if (NULL != helohost && NULL == session->helohost) {
        session->helohost = strdup(helohost);
    }   // end if

    return SMFIS_CONTINUE;
}   // end function: yenmamfi_helo

/**
 * Handle the envelope FROM command.
 * @param ctx Opaque context structure.
 * @param argv Null-terminated SMTP command arguments; argv[0] is guaranteed
 *             to be the sender address. Later arguments are the ESMTP arguments.
 * @return SMFIS_CONTINUE, SMFIS_TEMPFAIL, SMFIS_REJECT, SMFIS_DISCARD, SMFIS_ACCEPT
 */
static sfsistat
yenmamfi_envfrom(SMFICTX *ctx, char **argv)
{
    LogDebug("%s called: EnvFrom=%s", __func__, NNSTR(argv[0]));

    YenmaSession *session = NULL;
    RESTORE_YENMASESSION(ctx, session);

    // 2回目以降のトランザクションの場合に備えて掃除
    YenmaSession_reset(session);

    // context init
    if (!(session->ctx->cfg->milter_lazy_qid_fetch)) {
        yenma_set_qid(ctx, session);
    }   // end if

    // [SPF] Storing the envelope from
    session->raw_envfrom = strdup(argv[0]);
    if (NULL == session->raw_envfrom) {
        LogError("envelope from address duplication failed: errno=%s", strerror(errno));
        return yenma_tempfail(session);
    }   // end if
    char *mailaddr_tail = STRTAIL(session->raw_envfrom);
    const char *nextp, *errptr;
    session->envfrom =
        InetMailbox_buildSmtpReversePath(session->raw_envfrom, mailaddr_tail, &nextp, &errptr);
    if (NULL != session->envfrom) {
        // envelope from の parse 成功
        XSkip_fws(nextp, mailaddr_tail, &nextp);    // アドレスの後の FWS は見逃す
        if (nextp < mailaddr_tail) {
            // 文字列が余っている場合はパース失敗とみなし, session->envfrom を破棄する.
            LogNotice("envfrom has unused portion: envfrom=%s", session->raw_envfrom);
            InetMailbox_free(session->envfrom);
            session->envfrom = NULL;
        }   // end if
    } else {
        // envelope from の parse 失敗
        if (NULL == errptr) {
            LogError("InetMailbox_buildSmtpReversePath failed due to memory allocation error: errno=%s",
                     strerror(errno));
            return yenma_tempfail(session);
        } else {
            LogNotice("envfrom not parsable: envfrom=%s", session->raw_envfrom);
        }   // end if
    }   // end if

    return SMFIS_CONTINUE;
}   // end function: yenmamfi_envfrom

/**
 * Handle a message header.
 * @param ctx Opaque context structure.
 * @param headerf Header field name.
 * @param headerv Header field value. The content of the header may include folded
 *                white space (i.e. multiple lines with following white space).
 *                The trailing line terminator (CR/LF) is removed.
 * @return SMFIS_CONTINUE, SMFIS_TEMPFAIL, SMFIS_REJECT, SMFIS_DISCARD, SMFIS_ACCEPT
 */
static sfsistat
yenmamfi_header(SMFICTX *ctx, char *headerf, char *headerv)
{
#if defined(DEBUG)
    LogDebug("%s called: headerf=%s, headerv=%s", __func__, NNSTR(headerf), NNSTR(headerv));
#endif

    YenmaSession *session = NULL;
    RESTORE_YENMASESSION(ctx, session);

    if (session->ctx->cfg->milter_lazy_qid_fetch && NULL == session->qid) {
        // postfix に対応させるため, qid の取得を遅らせる
        yenma_set_qid(ctx, session);
    }   // end if

    // [AUTHRESULT] 削るべきヘッダの番号を保存する
    if (0 == strcasecmp(AUTHRESULTSHDR, headerf)) {
        // Authentication-Results ヘッダ に遭遇
        ++(session->authhdr_count);
        const char *p = headerv;
        if (session->keep_leading_header_space && (' ' == *p)) {
            // SMFIP_HDR_LEADSPC support
            ++p;
        }   // end if
        if (AuthResult_compareAuthservId(p, session->ctx->cfg->authresult_servid)) {
            // Authentication-Results ヘッダについてるホスト名がこれからつけるホスト名と同一
            // 削除対象ヘッダとして覚えておく
            if (0 > IntArray_append(session->delauthhdr, session->authhdr_count)) {
                LogError("IntArray_append failed: errno=%s", strerror(errno));
                return yenma_tempfail(session);
            }   // end if
            LogDebug("fraud AuthResultHeader: [No.%d] %s", session->authhdr_count, headerv);
        }   // end if
    }   // end if

    // [SIDF, DKIM] ヘッダを格納する
    if (session->ctx->cfg->dkim_verify || session->ctx->cfg->sidf_verify) {
        int pos = InetMailHeaders_append(session->headers, headerf, headerv);
        if (pos < 0) {
            LogNoResource();
            return yenma_tempfail(session);
        }   // end if
    }   // end if

    return SMFIS_CONTINUE;
}   // end function: yenmamfi_header

/**
 * Handle the end of message headers.
 * @param ctx Opaque context structure.
 * @return SMFIS_CONTINUE, SMFIS_TEMPFAIL, SMFIS_REJECT, SMFIS_DISCARD, SMFIS_ACCEPT
 */
static sfsistat
yenmamfi_eoh(SMFICTX *ctx)
{
    LogDebug("%s called", __func__);

    YenmaSession *session = NULL;
    RESTORE_YENMASESSION(ctx, session);

    // [DKIM] DKIM 検証処理の可否の判断
    if (session->ctx->cfg->dkim_verify) {
        // initialize DkimVerifier object
        DkimStatus setup_stat =
            DkimVerifier_new(session->ctx->dkim_vpolicy, session->resolver, session->headers,
                             session->keep_leading_header_space, &(session->verifier));
        if (DSTAT_INFO_NO_SIGNHEADER == setup_stat) {
            // No DKIM-Signature headers are found
            LogDebug("[DKIM-skip] No DKIM-Signature header found and verification is skipped.");
        } else if (DSTAT_ISCRITERR(setup_stat)) {
            LogError("DkimVerifier_setup failed: error=%s", DkimStatus_getSymbol(setup_stat));
            return yenma_tempfail(session);
        }   // end if

        // canonicalization 後データのダンプを設定
        if (NULL != session->ctx->cfg->dkim_canon_dump_dir) {
            (void) DkimVerifier_enableC14nDump(session->verifier,
                                               session->ctx->cfg->dkim_canon_dump_dir,
                                               session->qid);
        }   // end if
    }   // end if

    return SMFIS_CONTINUE;
}   // end function: yenmamfi_eoh

/**
 * Handle a piece of a message's body.
 * @param ctx Opaque context structure.
 * @param bodyp Pointer to the start of this block of body data. bodyp is not
 *              valid outside this call to xxfi_body.
 * @param len The amount of data pointed to by bodyp.
 */
static sfsistat
yenmamfi_body(SMFICTX *ctx, unsigned char *bodyp, size_t bodylen)
{
#if defined(DEBUG)
    LogDebug("%s called", __func__);
#endif

    YenmaSession *session = NULL;
    RESTORE_YENMASESSION(ctx, session);

    if (session->ctx->cfg->dkim_verify) {
        DkimStatus body_stat = DkimVerifier_updateBody(session->verifier, bodyp, bodylen);
        if (DSTAT_ISCRITERR(body_stat)) {
            LogError("DkimVerifier_body failed: error=%s", DkimStatus_getSymbol(body_stat));
            return yenma_tempfail(session);
        }   // end if
    }   // end if

    return SMFIS_CONTINUE;
}   // end function: yenmamfi_body

/**
 * End of a message.
 * @param ctx Opaque context structure.
 * @return SMFIS_CONTINUE, SMFIS_TEMPFAIL, SMFIS_REJECT, SMFIS_DISCARD, SMFIS_ACCEPT
 */
static sfsistat
yenmamfi_eom(SMFICTX *ctx)
{
    LogDebug("%s called", __func__);

    YenmaSession *session = NULL;
    RESTORE_YENMASESSION(ctx, session);

    // delete the Authentication-Results header(s)
    size_t authhdr_num = IntArray_getCount(session->delauthhdr);
    for (size_t n = 0; n < authhdr_num; ++n) {
        int change_stat =
            smfi_chgheader(ctx, AUTHRESULTSHDR, IntArray_get(session->delauthhdr, n), NULL);
        if (MI_SUCCESS != change_stat) {
            LogWarning("smfi_chgheader failed: [No.%d] %s",
                       IntArray_get(session->delauthhdr, n), AUTHRESULTSHDR);
        }   // end if
    }   // end for

    // prepare Authentication-Results header
    if (session->keep_leading_header_space) {
        // SMFIP_HDR_LEADSPC support
        AuthResult_appendChar(session->authresult, false, ' ');
    }   // end if
    bool append_stat = AuthResult_appendAuthServId(session->authresult,
                                                   session->ctx->cfg->authresult_servid);
    if (!append_stat) {
        LogNoResource();
        return yenma_tempfail(session);
    }   // end if

    // SPF evaluation
    if (session->ctx->cfg->spf_verify && !yenma_spfv_eom(session)) {
        return yenma_tempfail(session);
    }   // end if

    // Sender ID evaluation
    if (session->ctx->cfg->sidf_verify && !yenma_sidfv_eom(session)) {
        return yenma_tempfail(session);
    }   // end if

    // DKIM verification
    if (session->ctx->cfg->dkim_verify && !yenma_dkimv_eom(session)) {
        return yenma_tempfail(session);
    }   // end if

    // DMARC
    if (session->ctx->cfg->dmarc_verify && !yenma_dmarcv_eom(session)) {
        return yenma_tempfail(session);
    }   // end if

    if (0 != AuthResult_status(session->authresult)) {
        LogNoResource();
        return yenma_tempfail(session);
    }   // end if

    // take actions
    sfsistat eom_action = SMFIS_CONTINUE;
    int action_stat = yenma_invoke_actions(ctx, session, &eom_action);
    if (MI_SUCCESS != action_stat) {
        return yenma_tempfail(session);
    }   // end if

    // update score statistics
    AuthStatistics_increment(session->ctx->stats,
                             session->validated_result->spf_score,
                             session->validated_result->sidf_score,
                             session->validated_result->dkim_score,
                             session->validated_result->dkim_adsp_score,
                             session->validated_result->dmarc_score);

    // reset the session
    YenmaSession_reset(session);
    (void) LogHandler_setPrefix(NULL);

    return eom_action;
}   // end function: yenmamfi_eom

/**
 * Handle the current message's being aborted.
 * @param ctx Opaque context structure.
 * @return SMFIS_CONTINUE, SMFIS_TEMPFAIL, SMFIS_REJECT, SMFIS_DISCARD, SMFIS_ACCEPT
 */
static sfsistat
yenmamfi_abort(SMFICTX *ctx)
{
    LogDebug("%s called", __func__);

    YenmaSession *session = (YenmaSession *) smfi_getpriv(ctx);
    if (NULL != session) {
        YenmaSession_reset(session);
    }   // end if
    LogHandler_setPrefix(NULL);

    return SMFIS_CONTINUE;
}   // end function: yenmamfi_abort

/**
 * The current connection is being closed.
 * @param ctx Opaque context structure.
 * @return SMFIS_CONTINUE
 */
static sfsistat
yenmamfi_close(SMFICTX *ctx)
{
    LogDebug("%s called", __func__);

    YenmaSession *session = (YenmaSession *) smfi_getpriv(ctx);
    if (NULL != session) {
        YenmaSession_free(session);
        smfi_setpriv(ctx, NULL);

        int counter_stat = AtomicCounter_decrement(g_yenma_conn_counter);
        if (0 != counter_stat) {
            // ここでエラーが発生しても graceful shutdown ができなくなるだけなので処理は続行
            LogWarning("failed to decrement milter connection counter: errno=%s",
                       strerror(counter_stat));
        }   // end if
    }   // end if

    // OpenSSL にメモリリークさせないために必要
    ERR_remove_state(0);

    return SMFIS_CONTINUE;
}   // end function: yenmamfi_close

struct smfiDesc yenma_descr = {
    MILTERNAME, // filter name
    SMFI_VERSION,   // version code
    YENMA_MILTER_ACTION_FLAGS,  // flags
    yenmamfi_connect,   // connection info filter
    yenmamfi_helo,  // SMTP HELO command filter
    yenmamfi_envfrom,   // envelope sender filter
    NULL,   // envelope recipient filter
    yenmamfi_header,    // header filter
    yenmamfi_eoh,   // end of header
    yenmamfi_body,  // body block filter
    yenmamfi_eom,   // end of message
    yenmamfi_abort, // message aborted
    yenmamfi_close, // connection cleanup
#if defined(HAVE_MILTER_XXFI_NEGOTIATE)
    NULL,   // any unrecognized or unimplemented command filter
    NULL,   // SMTP DATA command filter
    yenmamfi_negotiate, // negotiation callback
#endif
};
