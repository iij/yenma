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

#ifndef __AUTH_STATS_H__
#define __AUTH_STATS_H__

#include <stdint.h>
#include <pthread.h>

#include "spf.h"
#include "dkim.h"
#include "dmarc.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct AuthStatistics {
    pthread_mutex_t lock;
    // スコアは列挙型の値をインデックスとする配列に格納する.
    // 配列の各要素は64ビットなので, 2^64 ≒ 1845京 を越えるとオーバーフローする.
    uint64_t spf[SPF_SCORE_MAX];
    uint64_t sidf[SPF_SCORE_MAX];
    uint64_t dkim[DKIM_BASE_SCORE_MAX];
    uint64_t dkim_adsp[DKIM_ADSP_SCORE_MAX];
    uint64_t dmarc[DMARC_SCORE_MAX];
} AuthStatistics;

extern AuthStatistics *AuthStatistics_new(void);
extern void AuthStatistics_free(AuthStatistics *self);
extern void AuthStatistics_reset(AuthStatistics *self, AuthStatistics *copy);
extern void AuthStatistics_copy(const AuthStatistics *self, AuthStatistics *copy);
extern void AuthStatistics_increment(AuthStatistics *self, SpfScore spf_score, SpfScore sidf_score,
                                     DkimBaseScore dkim_score, DkimAdspScore dkim_adsp_score,
                                     DmarcScore dmarc_score);
extern void AuthStatistics_dump(const AuthStatistics *self);

#ifdef __cplusplus
}
#endif

#endif /* __AUTH_STATS_H__ */
