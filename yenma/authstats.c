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

#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <syslog.h>

#include "loghandler.h"
#include "spf.h"
#include "dkim.h"
#include "dmarc.h"
#include "authstats.h"

AuthStatistics *
AuthStatistics_new(void)
{
    AuthStatistics *self = (AuthStatistics *) malloc(sizeof(AuthStatistics));
    if (NULL == self) {
        return NULL;
    }   // end if
    memset(self, 0, sizeof(AuthStatistics));

    int ret = pthread_mutex_init(&(self->lock), NULL);
    if (0 != ret) {
        free(self);
        return NULL;
    }   // end if

    return self;
}   // end function: AuthStatistics_new

void
AuthStatistics_free(AuthStatistics *self)
{
    if (NULL == self) {
        return;
    }   // end if
    (void) pthread_mutex_destroy(&(self->lock));
    free(self);
}   // end function: AuthStatistics_free

void
AuthStatistics_reset(AuthStatistics *self, AuthStatistics *copy)
{
    assert(NULL != self);

    int ret = pthread_mutex_lock(&(self->lock));
    if (0 != ret) {
        LogError("pthread_mutex_init failed: errno=%s", strerror(ret));
        return;
    }   // end if

    if (NULL != copy) {
        memcpy(&(copy->spf), &(self->spf), sizeof(self->spf));
        memcpy(&(copy->sidf), &(self->sidf), sizeof(self->sidf));
        memcpy(&(copy->dkim), &(self->dkim), sizeof(self->dkim));
        memcpy(&(copy->dkim_adsp), &(self->dkim_adsp), sizeof(self->dkim_adsp));
        memcpy(&(copy->dmarc), &(self->dmarc), sizeof(self->dmarc));
    }   // end if

    memset(&(self->spf), 0, sizeof(self->spf));
    memset(&(self->sidf), 0, sizeof(self->sidf));
    memset(&(self->dkim), 0, sizeof(self->dkim));
    memset(&(self->dkim_adsp), 0, sizeof(self->dkim_adsp));
    memset(&(self->dmarc), 0, sizeof(self->dmarc));

    ret = pthread_mutex_unlock(&(self->lock));
    if (0 != ret) {
        LogError("pthread_mutex_unlock failed: errno=%s", strerror(ret));
    }   // end if
}   // end function: AuthStatistics_reset

void
AuthStatistics_copy(const AuthStatistics *self, AuthStatistics *copy)
{
    assert(NULL != self);
    assert(NULL != copy);

    int ret = pthread_mutex_lock((pthread_mutex_t *) &(self->lock));
    if (0 != ret) {
        LogError("pthread_mutex_init failed: errno=%s", strerror(ret));
        return;
    }   // end if

    memcpy(&(copy->spf), &(self->spf), sizeof(self->spf));
    memcpy(&(copy->sidf), &(self->sidf), sizeof(self->sidf));
    memcpy(&(copy->dkim), &(self->dkim), sizeof(self->dkim));
    memcpy(&(copy->dkim_adsp), &(self->dkim_adsp), sizeof(self->dkim_adsp));
    memcpy(&(copy->dmarc), &(self->dmarc), sizeof(self->dmarc));

    ret = pthread_mutex_unlock((pthread_mutex_t *) &(self->lock));
    if (0 != ret) {
        LogError("pthread_mutex_unlock failed: errno=%s", strerror(ret));
    }   // end if
}   // end function: AuthStatistics_copy

void
AuthStatistics_increment(AuthStatistics *self, SpfScore spf_score, SpfScore sidf_score,
                         DkimBaseScore dkim_score, DkimAdspScore dkim_adsp_score,
                         DmarcScore dmarc_score)
{
    assert(NULL != self);

    int ret = pthread_mutex_lock(&(self->lock));
    if (0 != ret) {
        LogError("pthread_mutex_init failed: errno=%s", strerror(ret));
        return;
    }   // end if

    ++(self->spf[spf_score]);
    ++(self->sidf[sidf_score]);
    ++(self->dkim[dkim_score]);
    ++(self->dkim_adsp[dkim_adsp_score]);
    ++(self->dmarc[dmarc_score]);

    ret = pthread_mutex_unlock(&(self->lock));
    if (0 != ret) {
        LogError("pthread_mutex_unlock failed: errno=%s", strerror(ret));
    }   // end if
}   // end function: AuthStatistics_increment

void
AuthStatistics_dump(const AuthStatistics *self)
{
    assert(NULL != self);
    AuthStatistics stats;
    AuthStatistics_copy(self, &stats);

    LogPlain("SPF statistics: none=%" PRIu64 ", neutral=%" PRIu64 ", pass=%" PRIu64 ", policy=%"
             PRIu64 ", hardfail=%" PRIu64 ", softfail=%" PRIu64 ", temperror=%" PRIu64
             ", permerror=%" PRIu64 ", systemerror=%" PRIu64, stats.spf[SPF_SCORE_NONE],
             stats.spf[SPF_SCORE_NEUTRAL], stats.spf[SPF_SCORE_PASS],
             stats.spf[SPF_SCORE_POLICY], stats.spf[SPF_SCORE_HARDFAIL],
             stats.spf[SPF_SCORE_SOFTFAIL], stats.spf[SPF_SCORE_TEMPERROR],
             stats.spf[SPF_SCORE_PERMERROR], stats.spf[SPF_SCORE_SYSERROR]);
    LogPlain("SIDF statistics: none=%" PRIu64 ", neutral=%" PRIu64 ", pass=%" PRIu64 ", policy=%"
             PRIu64 ", hardfail=%" PRIu64 ", softfail=%" PRIu64 ", temperror=%" PRIu64
             ", permerror=%" PRIu64 ", systemerror=%" PRIu64, stats.sidf[SPF_SCORE_NONE],
             stats.sidf[SPF_SCORE_NEUTRAL], stats.sidf[SPF_SCORE_PASS],
             stats.sidf[SPF_SCORE_POLICY], stats.sidf[SPF_SCORE_HARDFAIL],
             stats.sidf[SPF_SCORE_SOFTFAIL], stats.sidf[SPF_SCORE_TEMPERROR],
             stats.sidf[SPF_SCORE_PERMERROR], stats.sidf[SPF_SCORE_SYSERROR]);
    LogPlain("DKIM statistics: none=%" PRIu64 ", pass=%" PRIu64 ", fail=%" PRIu64 "," " policy=%"
             PRIu64 ", neutral=%" PRIu64 ", temperror=%" PRIu64 ", permerror=%" PRIu64,
             stats.dkim[DKIM_BASE_SCORE_NONE], stats.dkim[DKIM_BASE_SCORE_PASS],
             stats.dkim[DKIM_BASE_SCORE_FAIL], stats.dkim[DKIM_BASE_SCORE_POLICY],
             stats.dkim[DKIM_BASE_SCORE_NEUTRAL], stats.dkim[DKIM_BASE_SCORE_TEMPERROR],
             stats.dkim[DKIM_BASE_SCORE_PERMERROR]);
    LogPlain("DKIM-ADSP statistics: none=%" PRIu64 ", pass=%" PRIu64 ", unknown=%" PRIu64 ", fail=%"
             PRIu64 ", discard=%" PRIu64 ", nxdomain=%" PRIu64 ", temperror=%" PRIu64
             ", permerror=%" PRIu64, stats.dkim_adsp[DKIM_ADSP_SCORE_NONE],
             stats.dkim_adsp[DKIM_ADSP_SCORE_PASS], stats.dkim_adsp[DKIM_ADSP_SCORE_UNKNOWN],
             stats.dkim_adsp[DKIM_ADSP_SCORE_FAIL], stats.dkim_adsp[DKIM_ADSP_SCORE_DISCARD],
             stats.dkim_adsp[DKIM_ADSP_SCORE_NXDOMAIN], stats.dkim_adsp[DKIM_ADSP_SCORE_TEMPERROR],
             stats.dkim_adsp[DKIM_ADSP_SCORE_PERMERROR]);
    LogPlain("DMARC statistics: none=%" PRIu64 ", pass=%" PRIu64 ", fail=%" PRIu64 ", policy=%"
             PRIu64 ", temperror=%" PRIu64 ", permerror=%" PRIu64, stats.dmarc[DMARC_SCORE_NONE],
             stats.dmarc[DMARC_SCORE_PASS], stats.dmarc[DMARC_SCORE_FAIL],
             stats.dmarc[DMARC_SCORE_POLICY], stats.dmarc[DMARC_SCORE_TEMPERROR],
             stats.dmarc[DMARC_SCORE_PERMERROR]);
}   // end function: AuthStatistics_syslog
