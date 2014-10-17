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

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>

#include "ptrop.h"
#include "inetmailbox.h"
#include "resolverpool.h"
#include "yenmacontext.h"
#include "yenmaconfig.h"
#include "yenmasession.h"
#include "validatedresult.h"

/**
 * create YenmaSession object
 * @return initialized YenmaSession object, or NULL if memory allocation failed.
 */
YenmaSession *
YenmaSession_new(YenmaContext *yenmactx)
{
    YenmaSession *self = (YenmaSession *) malloc(sizeof(YenmaSession));
    if (NULL == self) {
        return NULL;
    }   // end if
    memset(self, 0, sizeof(YenmaSession));

    self->ctx = yenmactx;
    self->keep_leading_header_space = false;

    self->delauthhdr = IntArray_new(0);
    if (NULL == self->delauthhdr) {
        goto cleanup;
    }   // end if

    self->authresult = AuthResult_new();
    if (NULL == self->authresult) {
        goto cleanup;
    }   // end if

    self->headers = InetMailHeaders_new(0);
    if (NULL == self->headers) {
        goto cleanup;
    }   // end if

    self->validated_result = ValidatedResult_new();
    if (NULL == self->validated_result) {
        goto cleanup;
    }   // end if
    return self;

  cleanup:
    YenmaSession_free(self);
    return NULL;
}   // end function: YenmaSession_new

/**
 * Reset the YenmaSession object.
 * The allocated memory is maintained.
 * @param self YenmaSession object to be reset
 */
void
YenmaSession_reset(YenmaSession *self)
{
    assert(NULL != self);

    PTRINIT(self->raw_envfrom);
    PTRINIT(self->qid);
    if (NULL != self->delauthhdr) {
        IntArray_reset(self->delauthhdr);
    }   // end if
    if (NULL != self->authresult) {
        AuthResult_reset(self->authresult);
    }   // end if
    self->authhdr_count = 0;
    if (NULL != self->spfevaluator) {
        SpfEvaluator_reset(self->spfevaluator);
    }   // end if
    if (NULL != self->sidfevaluator) {
        SpfEvaluator_reset(self->sidfevaluator);
    }   // end if
    if (NULL != self->verifier) {
        DkimVerifier_free(self->verifier);
        self->verifier = NULL;
    }   // end if
    if (NULL != self->aligner) {
        DmarcAligner_free(self->aligner);
        self->aligner = NULL;
    }   // end if
    if (NULL != self->envfrom) {
        InetMailbox_free(self->envfrom);
        self->envfrom = NULL;
    }   // end if
    if (NULL != self->headers) {
        InetMailHeaders_reset(self->headers);
    }   // end if
    if (NULL != self->validated_result) {
        ValidatedResult_reset(self->validated_result);
    }   // end if
}   // end function: YenmaSession_reset

/**
 * Release the YenmaSession object.
 * @param self YenmaSession object to be released
 */
void
YenmaSession_free(YenmaSession *self)
{
    if (NULL == self) {
        return;
    }   // end if

    free(self->raw_envfrom);
    free(self->qid);
    free(self->hostaddr);
    free(self->helohost);
    IntArray_free(self->delauthhdr);
    AuthResult_free(self->authresult);
    SpfEvaluator_free(self->spfevaluator);
    SpfEvaluator_free(self->sidfevaluator);
    DkimVerifier_free(self->verifier);
    DmarcAligner_free(self->aligner);
    InetMailHeaders_free(self->headers);
    ResolverPool_release(self->ctx->resolver_pool, self->resolver);
    InetMailbox_free(self->envfrom);
    ValidatedResult_free(self->validated_result);
    YenmaContext_unref(self->ctx);
    free(self);
}   // end function: YenmaSession_free
