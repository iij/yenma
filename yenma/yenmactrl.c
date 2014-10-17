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

#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <libmilter/mfapi.h>

#if defined(HAVE_LIBWRAP) && defined(HAVE_TCPD_H)
#include <tcpd.h>
#endif

#include "ptrop.h"
#include "loghandler.h"
#include "socketreader.h"
#include "socketwriter.h"
#include "socketaddress.h"
#include "xbuffer.h"
#include "keywordmap.h"
#include "listenerthread.h"
#include "protocolhandler.h"
#include "spf.h"
#include "dkim.h"
#include "dmarc.h"
#include "authstats.h"
#include "yenma.h"
#include "yenmacontext.h"
#include "yenmactrl.h"

static bool YenmaCtrl_onShowCounter(ProtocolHandler *handler, const char *param);
static bool YenmaCtrl_onResetCounter(ProtocolHandler *handler, const char *param);
static bool YenmaCtrl_onReload(ProtocolHandler *handler, const char *param);
static bool YenmaCtrl_onShutdown(ProtocolHandler *handler, const char *param);
static bool YenmaCtrl_onQuit(ProtocolHandler *handler, const char *param);
static bool YenmaCtrl_onGraceful(ProtocolHandler *handler, const char *param);
static bool YenmaCtrl_onUndefined(ProtocolHandler *handler, const char *param);

static const CommandHandlerMap yenma_ctrl_table[] = {
    {"SHOW-COUNTER", YenmaCtrl_onShowCounter},
    {"RESET-COUNTER", YenmaCtrl_onResetCounter},
    {"RELOAD", YenmaCtrl_onReload},
    {"SHUTDOWN", YenmaCtrl_onShutdown},
    {"QUIT", YenmaCtrl_onQuit},
    {"GRACEFUL", YenmaCtrl_onGraceful},
    {NULL, YenmaCtrl_onUndefined},
};

typedef enum YenmaStatsFormat {
    YENMA_STATS_FORMAT_NULL = 0,
    YENMA_STATS_FORMAT_PLAIN,
    YENMA_STATS_FORMAT_JSON,
} YenmaStatsFormat;

static const KeywordMap stats_url_tbl[] = {
    {"plain", YENMA_STATS_FORMAT_PLAIN},
    {"json", YENMA_STATS_FORMAT_JSON},
    {NULL, YENMA_STATS_FORMAT_NULL},
};

typedef const char *Enum_lookupScoreByValue(int);

typedef void YenmaCtrl_writeStatistics(SocketWriter *, const char *, const uint64_t[], size_t, Enum_lookupScoreByValue *);

static void
YenmaCtrl_writePlainStatistics(SocketWriter *swriter, const char *mech, const uint64_t scores[],
                          size_t score_len, Enum_lookupScoreByValue *score2keyword)
{
    for (size_t n = 0; n < score_len; ++n) {
        // 大半の処理系で enum が int で実装されていることに依存
        const char *score_name = score2keyword((int) n);
        SocketWriter_writeFormatString(swriter, "%s-%s: %" PRIu64 "\n", mech,
                                       score_name ? score_name : "null", scores[n]);
    }   // end for
}   // end function: YenmaCtrl_writePlainStatistics

static void
YenmaCtrl_writeJsonStatistics(SocketWriter *swriter, const char *mech, const uint64_t scores[],
                          size_t score_len, Enum_lookupScoreByValue *score2keyword)
{
    SocketWriter_writeFormatString(swriter, "  \"%s\": {\n", mech);
    for (size_t n = 0; n < score_len; ++n) {
        // 大半の処理系で enum が int で実装されていることに依存
        const char *score_name = score2keyword((int) n);
        SocketWriter_writeFormatString(swriter, "    \"%s\": %" PRIu64 ",\n",
                                       score_name ? score_name : "null", scores[n]);
    }   // end for
    SocketWriter_writeString(swriter, "  },\n");
}   // end function: YenmaCtrl_writeJsonStatistics

static YenmaStatsFormat
YenmaCtrl_parseRequestURL(const char *param)
{
    if (NULL == param) {
        return YENMA_STATS_FORMAT_NULL;
    }   // end if

    const char *param_tail = STRTAIL(param);
    if ('/' == *(param_tail - 1)) { // trim trailing '/'
        --param_tail;
    }   // end if

    if ('/' == *param) { // trim leading '/'
        ++param;
    }   // end if

    if (param_tail <= param) {
        return YENMA_STATS_FORMAT_NULL;
    }   // end if

    return KeywordMap_lookupByCaseStringSlice(stats_url_tbl, param, param_tail);
}   // end function: YenmaCtrl_parseRequestURL

static void
YenmaCtrl_showStatistics(ProtocolHandler *handler, const AuthStatistics *stats, const char *param)
{
    YenmaStatsFormat stats_format = YenmaCtrl_parseRequestURL(param);
    YenmaCtrl_writeStatistics *YenmaCtrl_writeStatisticsFunc = (YENMA_STATS_FORMAT_JSON == stats_format) ? YenmaCtrl_writeJsonStatistics : YenmaCtrl_writePlainStatistics;

    if (YENMA_STATS_FORMAT_JSON == stats_format) {
        SocketWriter_writeString(handler->swriter, "{\n");
    }   // end if

    YenmaCtrl_writeStatisticsFunc(handler->swriter, "spf", stats->spf, SPF_SCORE_MAX,
                              (Enum_lookupScoreByValue *) SpfEnum_lookupScoreByValue);
    YenmaCtrl_writeStatisticsFunc(handler->swriter, "sidf", stats->sidf, SPF_SCORE_MAX,
                              (Enum_lookupScoreByValue *) SpfEnum_lookupScoreByValue);
    YenmaCtrl_writeStatisticsFunc(handler->swriter, "dkim", stats->dkim, DKIM_BASE_SCORE_MAX,
                              (Enum_lookupScoreByValue *) DkimEnum_lookupScoreByValue);
    YenmaCtrl_writeStatisticsFunc(handler->swriter, "dkim-adsp", stats->dkim_adsp, DKIM_ADSP_SCORE_MAX,
                              (Enum_lookupScoreByValue *) DkimEnum_lookupAdspScoreByValue);
    YenmaCtrl_writeStatisticsFunc(handler->swriter, "dmarc", stats->dmarc, DMARC_SCORE_MAX,
                              (Enum_lookupScoreByValue *) DmarcEnum_lookupScoreByValue);

    if (YENMA_STATS_FORMAT_JSON == stats_format) {
        SocketWriter_writeString(handler->swriter, "}\n");
    }   // end if

    SocketWriter_flush(handler->swriter);
}   // end function: YenmaCtrl_showStatistics

static bool
YenmaCtrl_onShowCounter(ProtocolHandler *handler, const char *param)
// XXX エラーハンドリング, ロギング
{
    AuthStatistics stats;
    AuthStatistics_copy(g_yenma_ctx->stats, &stats);
    YenmaCtrl_showStatistics(handler, &stats, param);
    return false;
}   // end function: YenmaCtrl_onShowCounter

static bool
YenmaCtrl_onResetCounter(ProtocolHandler *handler, const char *param)
// XXX エラーハンドリング, ロギング
{
    AuthStatistics stats;
    AuthStatistics_reset(g_yenma_ctx->stats, &stats);
    YenmaCtrl_showStatistics(handler, &stats, param);
    return false;
}   // end function: YenmaCtrl_onResetCounter

static YenmaContext *
YenmaCtrl_rebuildContext(YenmaContext *oldctx)
{
    YenmaContext *newctx = YenmaContext_new();
    if (NULL == newctx) {
        LogError("YenmaContext_new failed: errno=%s", strerror(errno));
        goto cleanup;
    }   // end if

    // 設定ファイルの再読込
    newctx->cfg = YenmaConfig_new();
    if (NULL == newctx->cfg) {
        LogError("YenmaConfig_new failed: errno=%s", strerror(errno));
        goto cleanup;
    }   // end if

    if (!YenmaConfig_load(newctx->cfg, oldctx->config_file)) {
        LogWarning("failed to reload configuration: file=%s", oldctx->config_file);
        goto cleanup;
    }   // end switch

    if (!YenmaContext_buildPolicies(newctx, newctx->cfg)) {
        goto cleanup;
    }   // end if

    // delegates unreloadable attributes
    newctx->argc = oldctx->argc;
    newctx->argv = oldctx->argv;
    newctx->config_file = oldctx->config_file;
    newctx->yenmactrl = oldctx->yenmactrl;
    newctx->graceful_shutdown = oldctx->graceful_shutdown;
    newctx->stats = oldctx->stats;

    return newctx;

  cleanup:
    if (NULL != newctx) {
        YenmaContext_unref(newctx);
    }   // end if
    return NULL;
}   // end function: YenmaCtrl_rebuildContext

static bool
YenmaCtrl_onReload(ProtocolHandler *handler, const char *param __attribute__((unused)))
// XXX エラーハンドリング, ロギング
{
    int ret;
    YenmaContext *newctx = NULL;

    LogInfo("reloading configurations");

    YenmaContext *oldctx = yenma_get_context_reference();
    if (NULL == oldctx) {
        goto cleanup;
    }   // end if

    newctx = YenmaCtrl_rebuildContext(oldctx);
    if (NULL == newctx) {
        LogError("Context rebuilding failed");
        goto cleanup;
    }   // end if
    ++newctx->refcount; // instead of YenmaContext_ref()

    // ロックの取得
    ret = pthread_rwlock_timedwrlock(&g_yenma_ctx_lock, &g_yenma_ctx_lock_timeout);
    if (0 != ret) {
        LogError("pthread_rwlock_timedwrlock failed: errno=%s", strerror(ret));
        goto cleanup;
    }   // end if

    // YenmaContext を入れ換える
    bool reloaded;
    if (oldctx == g_yenma_ctx) {
        // oldctx が入れ替わっていないことが確認できたら, 新しいコンテキストと入れ換える
        g_yenma_ctx = newctx;
        reloaded = true;
    } else {
        // oldctx が入れ替わっていた場合は入れ換えを中止
        reloaded = false;
    }   // end if

    ret = pthread_rwlock_unlock(&g_yenma_ctx_lock);
    if (0 != ret) {
        LogError("pthread_rwlock_unlock failed: errno=%s", strerror(ret));
    }   // end if

    if (!reloaded) {
        LogError("Context replacing failed");
        goto cleanup;
    }   // end if

    LogInfo("MilterControl: reconfiguration succeeded");
    YenmaConfig_dump(newctx->cfg);
    YenmaContext_unref(newctx);

    oldctx->free_unreloadables = false;
    YenmaContext_unref(oldctx); // for temporary reference
    YenmaContext_unref(oldctx); // for global reference

    SocketWriter_writeString(handler->swriter, "200 RELOADED\n");
    SocketWriter_flush(handler->swriter);

    return false;

  cleanup:
    LogWarning("MilterControl: reconfiguration aborted");
    if (NULL != newctx) {
        newctx->free_unreloadables = false;
        YenmaContext_unref(newctx);
        YenmaContext_unref(newctx);
    }   // end if
    if (NULL != oldctx) {
        YenmaContext_unref(oldctx);
    }   // end if

    SocketWriter_writeString(handler->swriter, "500 FAILED\n");
    SocketWriter_flush(handler->swriter);

    return false;
}   // end function: YenmaCtrl_onReload

static bool
YenmaCtrl_onShutdown(ProtocolHandler *handler, const char *param __attribute__((unused)))
// XXX エラーハンドリング, ロギング
{
    smfi_stop();
    ListenerThread_shutdown(g_yenma_ctx->yenmactrl);

    SocketWriter_writeString(handler->swriter, "200 SHUTDOWN ACCEPTED\n");
    SocketWriter_flush(handler->swriter);

    int32_t conn_counter = -1;
    (void) AtomicCounter_peek(g_yenma_conn_counter, &conn_counter);
    LogInfo("shutting down: connections=%" PRId32, conn_counter);

    return true;
}   // end function: YenmaCtrl_onShutdown

static bool
YenmaCtrl_onQuit(ProtocolHandler *handler, const char *param __attribute__((unused)))
// XXX エラーハンドリング, ロギング
{
    SocketWriter_writeString(handler->swriter, "200 OK\n");
    SocketWriter_flush(handler->swriter);

    return true;
}   // end function: YenmaCtrl_onQuit

static bool
YenmaCtrl_onGraceful(ProtocolHandler *handler, const char *param __attribute__((unused)))
// XXX エラーハンドリング, ロギング
{
    g_yenma_ctx->graceful_shutdown = true;
    smfi_stop();
    ListenerThread_shutdown(g_yenma_ctx->yenmactrl);

    SocketWriter_writeString(handler->swriter, "200 GRACEFUL SHUTDOWN ACCEPTED\n");
    SocketWriter_flush(handler->swriter);

    int32_t conn_counter = -1;
    (void) AtomicCounter_peek(g_yenma_conn_counter, &conn_counter);
    LogInfo("starting graceful shutdown: connections=%" PRId32, conn_counter);

    return true;
}   // end function: YenmaCtrl_onGraceful

static bool
YenmaCtrl_onUndefined(ProtocolHandler *handler, const char *param)
// XXX エラーハンドリング, ロギング
{
    SocketWriter_writeFormatString(handler->swriter, "500 UNKNOWN COMMAND: %s\n", param);
    SocketWriter_flush(handler->swriter);

    return false;
}   // end function: YenmaCtrl_onUndefined

static int
YenmaCtrl_onAccept(void *ctx, int fd, const struct sockaddr *addr, socklen_t addrlen)
{
#if defined(HAVE_LIBWRAP) && defined(HAVE_TCPD_H)
    struct request_info request;
    char addrstr[INET6_ADDRSTRLEN + 1];
    int gai_error = SockAddr_getNumericNameInfo(addr, &addrlen, false, addrstr, sizeof(addrstr));
    request_init(&request, RQ_DAEMON, LIBWRAP_DAEMON_NAME, RQ_FILE, fd, RQ_CLIENT_SIN, addr,
                 RQ_CLIENT_ADDR, (0 == gai_error) ? addrstr : NULL, 0);
    fromhost(&request);
    if (0 == hosts_access(&request)) {
        LogInfo("Access denied by libwrap: src=%s",
                (0 == gai_error) ? addrstr : gai_strerror(gai_error));
        return 0;
    }   // end if
#endif
    return ProtocolHandler_run(yenma_ctrl_table, fd, ctx);
}   // end function: YenmaCtrl_onAccept

YenmaCtrl *
YenmaCtrl_run(const char *control_socket, int backlog)
{
    return ListenerThread_create(control_socket, backlog, YenmaCtrl_onAccept, NULL);
}   // end function: YenmaCtrl_run

void
YenmaCtrl_shutdown(YenmaCtrl *self)
{
    ListenerThread_shutdown(self);
}   // end function: YenmaCtrl_shutdown

void
YenmaCtrl_free(YenmaCtrl *self)
{
    ListenerThread_free(self);
}   // end function: YenmaCtrl_free
