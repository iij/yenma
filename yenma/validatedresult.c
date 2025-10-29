/*
 * Copyright (c) 2007-2014 Internet Initiative Japan Inc. All rights reserved.
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

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "validatedresult.h"
#include "spf.h"
#include "dkim.h"
#include "inetmailbox.h"

/**
 * create ValidatedResult object
 * @return initialized ValidatedResult object, or NULL if memory allocation failed.
 */
ValidatedResult *
ValidatedResult_new(void)
{
    ValidatedResult *self = (ValidatedResult *) malloc(sizeof(ValidatedResult));
    if (NULL == self) {
        return NULL;
    }   // end if
    memset(self, 0, sizeof(ValidatedResult));

    self->spf_eval_address.envfrom = NULL;
    self->spf_score = SPF_SCORE_NULL;
    self->sidf_score = SPF_SCORE_NULL;
    self->dkim_score = DKIM_BASE_SCORE_NULL;
    self->dkim_adsp_score = DKIM_ADSP_SCORE_NULL;
    self->dmarc_score = DMARC_SCORE_NULL;

    return self;
}   // end function: ValidatedResult_new


/**
 * reset ValidatedResult object
 * @param self ValidatedResult object to reset
 */
void
ValidatedResult_reset(ValidatedResult *self)
{
    assert(NULL != self);

    if (self->spf_eval_by_sender) {
        if (NULL != self->spf_eval_address.envfrom) {
            InetMailbox_free(self->spf_eval_address.envfrom);
            self->spf_eval_address.envfrom = NULL;
        }   // end if
    } else {
        if (NULL != self->spf_eval_address.helohost) {
            free(self->spf_eval_address.helohost);
            self->spf_eval_address.helohost = NULL;
        }   // end if
    }   // end if
    self->spf_score = SPF_SCORE_NULL;
    self->sidf_score = SPF_SCORE_NULL;
    self->dkim_score = DKIM_BASE_SCORE_NULL;
    self->dkim_adsp_score = DKIM_ADSP_SCORE_NULL;
    self->dmarc_score = DMARC_SCORE_NULL;
}   // end function: ValidatedResult_reset

/**
 * release ValidatedResult object
 * @param self ValidatedResult object to release
 */
void
ValidatedResult_free(ValidatedResult *self)
{
    if (NULL == self) {
        return;
    }   // end if

    if (self->spf_eval_by_sender) {
        if (NULL != self->spf_eval_address.envfrom) {
            InetMailbox_free(self->spf_eval_address.envfrom);
            self->spf_eval_address.envfrom = NULL;
        }   // end if
    } else {
        if (NULL != self->spf_eval_address.helohost) {
            free(self->spf_eval_address.helohost);
            self->spf_eval_address.helohost = NULL;
        }   // end if
    }   // end if

    free(self);
}   // end function: ValidatedResult_free
