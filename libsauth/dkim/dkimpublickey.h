/*
 * Copyright (c) 2006-2015 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifndef __DKIM_PUBLIC_KEY_H__
#define __DKIM_PUBLIC_KEY_H__

#include <stdbool.h>
#include <openssl/evp.h>

#include "dnsresolv.h"
#include "dkim.h"
#include "dkimverificationpolicy.h"
#include "dkimtaglistobject.h"
#include "dkimsignature.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct DkimPublicKey DkimPublicKey;

extern DkimStatus DkimPublicKey_build(const DkimVerificationPolicy *policy, const char *keyval,
                                      const char *domain, DkimPublicKey **publickey);
extern void DkimPublicKey_free(DkimPublicKey *self);
extern DkimStatus DkimPublicKey_lookup(const DkimVerificationPolicy *policy,
                                       const DkimSignature *signature, DnsResolver *resolver,
                                       DkimPublicKey **publickey);
extern EVP_PKEY *DkimPublicKey_getPublicKey(const DkimPublicKey *self);
extern bool DkimPublicKey_isTesting(const DkimPublicKey *self);
extern bool DkimPublicKey_isSubdomainProhibited(const DkimPublicKey *self);
extern bool DkimPublicKey_isEMailServiceUsable(const DkimPublicKey *self);
extern DkimKeyType DkimPublicKey_getKeyType(const DkimPublicKey *self);
extern const char *DkimPublicKey_getGranularity(const DkimPublicKey *self);

#ifdef __cplusplus
}
#endif

#endif /* __DKIM_PUBLIC_KEY_H__ */
