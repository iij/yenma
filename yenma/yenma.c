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
#include <limits.h>
#include <netdb.h>
#include <pthread.h>
#include <pwd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sysexits.h>
#include <syslog.h>
#include <unistd.h>
#include <time.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <libmilter/mfapi.h>

#if defined(HAVE_LIBWRAP) && defined(HAVE_TCPD_H)
#include <tcpd.h>
#endif

#include "ptrop.h"
#include "stdaux.h"
#include "loghandler.h"
#include "cryptomutex.h"
#include "daemon_stuff.h"
#include "configloader.h"
#include "milteraux.h"
#include "atomiccounter.h"
#include "spf.h"
#include "dkim.h"
#include "authstats.h"
#include "yenmaconfig.h"
#include "yenmacontext.h"
#include "yenma.h"

// global variables
/// global variable to store YenmaContext object
YenmaContext *g_yenma_ctx = NULL;
pthread_rwlock_t g_yenma_ctx_lock = PTHREAD_RWLOCK_INITIALIZER;
const struct timespec g_yenma_ctx_lock_timeout = { YENMA_MUTEX_TIMEOUT, 0 };

/// counter of milter connections (which have YenmaSession instance)
AtomicCounter *g_yenma_conn_counter = NULL;

#define CTRLSOCKET_BACKLOG 5

#if defined(PACKAGE_VERSION)
#define YENMA_VERSION_INFO "v" PACKAGE_VERSION
#else
#define YENMA_VERSION_INFO "(build " __DATE__ " " __TIME__ ")"
#endif

static void
usage(FILE *fp)
{
    fprintf(fp, MILTERNAME " " YENMA_VERSION_INFO "\n");
    fprintf(fp, "[Usage]\n");
    fprintf(fp, "yenma [-c configuration-file] [-h]\n\n");
    fprintf(fp, "  -h    show this usage\n");
    exit(EX_USAGE);
}   // end function: usage

/**
 * the entry point.
 */
int
main(int argc, char **argv)
{
    LogHandler_init();
    if (0 < isatty(STDOUT_FILENO)) {
        LogHandler_switchToStdout();
    }   // end if

    // memory allocation
    g_yenma_ctx = YenmaContext_new();
    if (NULL == g_yenma_ctx) {
        LogNoResource();
        exit(EX_OSERR);
    }   // end if
    g_yenma_ctx->argc = argc;
    g_yenma_ctx->argv = argv;

    YenmaConfig *yenmacfg = YenmaConfig_new();
    if (NULL == yenmacfg) {
        LogNoResource();
        exit(EX_OSERR);
    }   // end if
    g_yenma_ctx->cfg = yenmacfg;

    int c;
    while (-1 != (c = getopt(argc, argv, "c:h"))) {
        switch (c) {
        case 'c':
            g_yenma_ctx->config_file = strdup(optarg);
            if (NULL == g_yenma_ctx->config_file) {
                LogNoResource();
                exit(EX_OSERR);
            }   // end if
            break;
        case 'h':
        default:
            usage(stdout);
            exit(EX_CONFIG);
        }   // end switch
    }   // end while

    // load configuration
    if (!YenmaConfig_load(yenmacfg, g_yenma_ctx->config_file)) {
        usage(stdout);
        exit(EX_CONFIG);
    }   // end if
    LogHandler_setLogMask(LOG_UPTO(yenmacfg->logging_mask));
    YenmaConfig_dump(yenmacfg);

    // syslog setup
    // not to refer to unallocated memory area after yenmacfg is released
    char *logident = strdup(yenmacfg->logging_ident);
    if (NULL == logident) {
        LogNoResource();
        exit(EX_OSERR);
    }   // end if
    openlog(logident, LOG_PID | LOG_NDELAY, yenmacfg->logging_facility);

    g_yenma_conn_counter = AtomicCounter_new();
    if (NULL == g_yenma_conn_counter) {
        LogNoResource();
        exit(EX_OSERR);
    }   // end if

    // initialization of statistics object
    g_yenma_ctx->stats = AuthStatistics_new();
    if (NULL == g_yenma_ctx->stats) {
        LogNoResource();
        exit(EX_OSERR);
    }   // end if

    if (!YenmaContext_buildPolicies(g_yenma_ctx, yenmacfg)) {
        exit(EX_CONFIG);
    }   // end if

    // milter setup
    const char *errstr = NULL;
    if (0 > milter_setup(&yenma_descr, yenmacfg->milter_socket, yenmacfg->milter_backlog,
                         yenmacfg->milter_timeout, yenmacfg->milter_debuglevel, &errstr)) {
        LogError("%s: milter_socket=%s, errno=%s", NNSTR(errstr), yenmacfg->milter_socket,
                 strerror(errno));
        exit(EX_UNAVAILABLE);
    }   // end if

    // setuid & daemonize
    if (0 > daemon_init(yenmacfg->service_user, yenmacfg->service_chdir, &errstr)) {
        LogError("%s: user=%s, rootdir=%s, errno=%s", NNSTR(errstr), yenmacfg->service_user,
                 yenmacfg->service_chdir, strerror(errno));
        exit(EX_UNAVAILABLE);
    }   // end if

    // must be after fork()
    PidFile *pidfile = PidFile_create(yenmacfg->service_pidfile, true, &errstr);
    if (NULL == pidfile) {
        LogError("failed to create pid file: file=%s, error=%s, errno=%s",
                 yenmacfg->service_pidfile, NNSTR(errstr), strerror(errno));
        exit(EX_CANTCREAT); // exit if it is failed to create pidfile
    }   // end if

    // it must be after fork() to spawn control thread.
    if (NULL != yenmacfg->service_controlsocket) {
#if defined(HAVE_LIBWRAP) && defined(HAVE_TCPD_H)
        // suppress syslog messages from libwrap
        allow_severity = 0;
        deny_severity = 0;
#endif
        g_yenma_ctx->yenmactrl = YenmaCtrl_run(yenmacfg->service_controlsocket, CTRLSOCKET_BACKLOG);
        if (NULL == g_yenma_ctx->yenmactrl) {
            LogError("control socket open failed: socket=%s", yenmacfg->service_controlsocket);
            exit(EX_CONFIG);
        }   // end if
    }   // end if

    // initialization of OpenSSL
    Crypto_mutex_init();

    LogNotice("yenma " YENMA_VERSION_INFO " starting up");  // for console

    if (!yenmacfg->service_hold_tty_open && 0 > close_tty()) {
        LogError("failed to close tty (/dev/null missing?): errno=%s", strerror(errno));
        exit(EX_OSFILE);
    }   // end if
    LogHandler_switchToSyslog();    // stdout is not available anymore

    LogNotice("yenma " YENMA_VERSION_INFO " starting up");  // for syslog

    // milter main function
    int smfi_main_status = smfi_main();

    if (g_yenma_ctx->graceful_shutdown) {
        int counter_stat = AtomicCounter_decrement(g_yenma_conn_counter);
        if (0 != counter_stat) {
            LogWarning("failed to decrement milter connection counter: errno=%s",
                       strerror(counter_stat));
        }   // end if
        LogInfo("waiting for all milter connections to be closed: timeout=%d[s]",
                (int) g_yenma_ctx->cfg->service_graceful_shutdown_timeout);
        counter_stat =
            AtomicCounter_wait0(g_yenma_conn_counter,
                                g_yenma_ctx->cfg->service_graceful_shutdown_timeout);
        switch (counter_stat) {
        case 0:
            LogInfo("all milter connections are closed");
            break;
        case ETIMEDOUT:
            LogInfo("timed out and gave up to wait");
            break;
        default:
            LogError("unexpected connection counter error: errno=%s", strerror(counter_stat));
            break;
        }   // end switch
    }   // end if

    int ret = pthread_rwlock_timedwrlock(&g_yenma_ctx_lock, &g_yenma_ctx_lock_timeout);
    if (0 != ret) {
        // pthread_rwlock_timedwrlock() がエラーを返したからといって中断もできない
        LogError("pthread_rwlock_timedwrlock failed: errno=%s", strerror(ret));
    }   // end if

    if (NULL != g_yenma_ctx->yenmactrl) {
        // waiting for the control thread to be shutdown
        YenmaCtrl_free(g_yenma_ctx->yenmactrl);
        g_yenma_ctx->yenmactrl = NULL;
    }   // end if
    AuthStatistics_dump(g_yenma_ctx->stats);

    PidFile_close(pidfile, true);
    pidfile = NULL;

    // cleanup
    YenmaContext_unref(g_yenma_ctx);
    g_yenma_ctx = NULL;
    AtomicCounter_free(g_yenma_conn_counter);
    g_yenma_conn_counter = NULL;

    ret = pthread_rwlock_unlock(&g_yenma_ctx_lock);
    if (0 != ret) {
        LogError("pthread_rwlock_unlock failed: errno=%s", strerror(ret));
    }   // end if

    // OpenSSL cleanup
    Crypto_mutex_cleanup();
    ERR_free_strings(); // XXX Is this needed even if ERR_load_crypto_strings() is not called?
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();

    LogNotice("yenma " YENMA_VERSION_INFO " shutting down");
    LogHandler_cleanup();
    closelog();
    free(logident);

    return smfi_main_status;
}   // end function: main
