/*
 * Copyright (c) 2006-2014 Internet Initiative Japan Inc. All rights reserved.
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

#include <sys/types.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <openssl/evp.h>

#include "dkimlogger.h"
#include "dkim.h"
#include "dkimenum.h"
#include "dkimverificationpolicy.h"

/**
 * create DkimVerificationPolicy object
 * @return initialized DkimVerificationPolicy object, or NULL if memory allocation failed.
 */
DkimVerificationPolicy *
DkimVerificationPolicy_new(void)
{
    DkimVerificationPolicy *self =
        (DkimVerificationPolicy *) malloc(sizeof(DkimVerificationPolicy));
    if (NULL == self) {
        return NULL;
    }   // end if
    memset(self, 0, sizeof(DkimVerificationPolicy));

    self->sign_header_limit = 0;
    self->author_limit = 0;
    self->accept_expired_signature = false;
    self->accept_future_signature = false;
    self->enable_atps = true;

    return self;
}   // end function: DkimVerificationPolicy_new

/**
 * release DkimVerificationPolicy object
 * @param self DkimVerificationPolicy object to release
 */
void
DkimVerificationPolicy_free(DkimVerificationPolicy *self)
{
    free(self);
}   // end function: DkimVerificationPolicy_free

/**
 * set the maximum number of DKIM-Signature headers to verify.
 * DKIM-Signature headers exceed this limit are ignored.
 * @param header_limit the maximum number of DKIM-Signature headers to verify
 *                     0 for unlimited (default).
 */
void
DkimVerificationPolicy_setSignHeaderLimit(DkimVerificationPolicy *self, size_t header_limit)
{
    assert(NULL != self);
    self->sign_header_limit = header_limit;
}   // end function: DkimVerificationPolicy_setSignHeaderLimit

/**
 * set the maximum number of the Authors to check their policy.
 * Authors exceed this limit are ignored.
 * @param header_limit the maximum number of DKIM-Signature headers to verify
 *                     0 for unlimited (default).
 */
void
DkimVerificationPolicy_setAuthorLimit(DkimVerificationPolicy *self, size_t author_limit)
{
    assert(NULL != self);
    self->author_limit = author_limit;
}   // end function: DkimVerificationPolicy_setAuthorLimit

/**
 * set whether or not to treat expired DKIM signatures as valid
 * @param flag true to accept, false to reject
 */
void
DkimVerificationPolicy_acceptExpiredSignature(DkimVerificationPolicy *self, bool flag)
{
    assert(NULL != self);
    self->accept_expired_signature = flag;
}   // end function: DkimVerificationPolicy_acceptExpiredSignature

/**
 * set whether or not to accept DKIM signatures signed in the future
 * @param flag true to accept, false to ignore
 */
void
DkimVerificationPolicy_acceptFutureSignature(DkimVerificationPolicy *self, bool flag)
{
    assert(NULL != self);
    self->accept_future_signature = flag;
}   // end function: DkimVerificationPolicy_acceptFutureSignature

/**
 * set whether or not to treat expired DKIM signatures as valid
 * @param accept true to accept, false to reject
 */
void
DkimVerificationPolicy_verifyAtpsDelegation(DkimVerificationPolicy *self, bool flag)
{
    assert(NULL != self);
    self->enable_atps = flag;
}   // end function: DkimVerificationPolicy_verifyAtpsDelegation

/**
* enable/disable RFC4871-compatible mode.
* Disabled by default (which means RFC6376-compliant).
* @param enable true to enable RFC4871 compatible mode, false to disable.
*/
void
DkimVerificationPolicy_setRfc4871Compatible(DkimVerificationPolicy *self, bool enable)
{
    assert(NULL != self);
    self->rfc4871_compatible = enable;
}   // end function: DkimVerificationPolicy_setRfc4871Compatible
