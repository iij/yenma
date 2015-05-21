/*
 * Copyright (c) 2008-2015 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifndef __YENMA_H__
#define __YENMA_H__

#include <sys/socket.h>
#include <pthread.h>
#include <time.h>
#include <libmilter/mfapi.h>

#include "atomiccounter.h"
#include "spf.h"
#include "dkim.h"
#include "dmarc.h"
#include "authstats.h"
#include "yenmactrl.h"
#include "yenmacontext.h"
#include "yenmaconfig.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MILTERNAME "yenma"
#if !defined(LIBWRAP_DAEMON_NAME)
#define LIBWRAP_DAEMON_NAME "yenma-control"
#endif
#define NOQID   "NO_QUEUEID"    // smfi_getsymval() で qid をとれなかった場合に使用する文字列
#define YENMA_MUTEX_TIMEOUT   60

// global variables
extern YenmaContext *g_yenma_ctx;
extern pthread_rwlock_t g_yenma_ctx_lock;
extern const struct timespec g_yenma_ctx_lock_timeout;
extern AtomicCounter *g_yenma_conn_counter;

extern struct smfiDesc yenma_descr;

extern YenmaContext *yenma_get_context_reference(void);

#ifdef __cplusplus
}
#endif

#endif /* __YENMA_H__ */
