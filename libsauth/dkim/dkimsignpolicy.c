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

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <sys/types.h>

#include "xskip.h"
#include "dkimlogger.h"
#include "strarray.h"
#include "xbuffer.h"
#include "ptrop.h"
#include "dkim.h"
#include "dkimenum.h"
#include "dkimsignpolicy.h"

/**
 * create DkimSignPolicy object
 * @return initialized DkimSignPolicy object, or NULL if memory allocation failed.
 */
DkimSignPolicy *
DkimSignPolicy_new(void)
{
    DkimSignPolicy *self = (DkimSignPolicy *) malloc(sizeof(DkimSignPolicy));
    if (NULL == self) {
        return NULL;
    }   // end if
    memset(self, 0, sizeof(DkimSignPolicy));

    self->signature_ttl = -1LL; // termless
    self->keytype = DKIM_KEY_TYPE_RSA;
    self->hashalg = DKIM_HASH_ALGORITHM_SHA256;
    self->canon_method_header = DKIM_C14N_ALGORITHM_RELAXED;
    self->canon_method_body = DKIM_C14N_ALGORITHM_SIMPLE;
    self->sign_header_with_crlf = true;

    return self;
}   // end function: DkimSignPolicy_new

/**
 * release DkimSignPolicy object
 * @param self DkimSignPolicy object to release
 */
void
DkimSignPolicy_free(DkimSignPolicy *self)
{
    free(self);
}   // end function: DkimSignPolicy_free

/**
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 */
DkimStatus
DkimSignPolicy_setCanonAlgorithm(DkimSignPolicy *self, const char *headercanon,
                                 const char *bodycanon)
{
    assert(NULL != self);

    if (NULL == headercanon || NULL == bodycanon) {
        DkimLogConfigError("empty value specified for %s canonicalization algorithm",
                           NULL == headercanon ? "header" : "body");
        return DSTAT_CFGERR_EMPTY_VALUE;
    }   // end if

    self->canon_method_header = DkimEnum_lookupC14nAlgorithmByName(headercanon);
    if (DKIM_C14N_ALGORITHM_NULL == self->canon_method_header) {
        DkimLogConfigError("undefined header canonicalization algorithm: canonalg=%s", headercanon);
        return DSTAT_CFGERR_UNDEFINED_KEYWORD;
    }   // end if

    self->canon_method_body = DkimEnum_lookupC14nAlgorithmByName(bodycanon);
    if (DKIM_C14N_ALGORITHM_NULL == self->canon_method_body) {
        DkimLogConfigError("undefined body canonicalization algorithm: canonalg=%s", bodycanon);
        return DSTAT_CFGERR_UNDEFINED_KEYWORD;
    }   // end if
    return DSTAT_OK;
}   // end function: DkimSignPolicy_setCanonAlgorithm

/**
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 */
DkimStatus
DkimSignPolicy_setHashAlgorithm(DkimSignPolicy *self, const char *hashalg)
{
    assert(NULL != self);

    if (NULL == hashalg) {
        DkimLogConfigError("empty value specified for hash algorithm");
        return DSTAT_CFGERR_EMPTY_VALUE;
    }   // end if

    self->hashalg = DkimEnum_lookupHashAlgorithmByName(hashalg);
    if (DKIM_HASH_ALGORITHM_NULL == self->hashalg) {
        DkimLogConfigError("undefined hash algorithm: hashalg=%s", hashalg);
        return DSTAT_CFGERR_UNDEFINED_KEYWORD;
    }   // end if
    return DSTAT_OK;
}   // end function: DkimSignPolicy_setHashAlgorithm

/**
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 */
DkimStatus
DkimSignPolicy_setAtpsHashAlgorithm(DkimSignPolicy *self, const char *atps_hashalg)
{
    assert(NULL != self);

    if (NULL == atps_hashalg) {
        DkimLogConfigError("empty value specified for hash algorithm");
        return DSTAT_CFGERR_EMPTY_VALUE;
    }   // end if

    self->atps_hashalg = DkimEnum_lookupAtpsHashAlgorithmByName(atps_hashalg);
    if (DKIM_HASH_ALGORITHM_NULL == self->atps_hashalg) {
        DkimLogConfigError("undefined atps hash algorithm: hashalg=%s", atps_hashalg);
        return DSTAT_CFGERR_UNDEFINED_KEYWORD;
    }   // end if
    return DSTAT_OK;
}   // end function: DkimSignPolicy_setAtpsHashAlgorithm

/**
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 */
DkimStatus
DkimSignPolicy_setKeyType(DkimSignPolicy *self, const char *pubkeyalg)
{
    assert(NULL != self);

    if (NULL == pubkeyalg) {
        DkimLogConfigError("empty value specified for public key algorithm");
        return DSTAT_CFGERR_EMPTY_VALUE;
    }   // end if

    self->keytype = DkimEnum_lookupKeyTypeByName(pubkeyalg);
    if (DKIM_KEY_TYPE_NULL == self->keytype) {
        DkimLogConfigError("undefined public key algorithm: pubkeyalg=%s", pubkeyalg);
        return DSTAT_CFGERR_UNDEFINED_KEYWORD;
    }   // end if
    return DSTAT_OK;
}   // end function: DkimSignPolicy_setKeyType

void
DkimSignPolicy_setSignatureTTL(DkimSignPolicy *self, long long signature_ttl)
{
    assert(NULL != self);
    self->signature_ttl = signature_ttl;
}   // end function: DkimSignPolicy_setSignatureTTL

void
DkimSignPolicy_setNewlineCharOfSignature(DkimSignPolicy *self, bool crlf)
{
    assert(NULL != self);
    self->sign_header_with_crlf = crlf;
}   // end function: DkimSignPolicy_setNewlineCharOfSignature
