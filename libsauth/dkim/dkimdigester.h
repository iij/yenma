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

#ifndef __DKIM_DIGESTER_H__
#define __DKIM_DIGESTER_H__

#include <openssl/evp.h>

#include "strarray.h"
#include "inetmailheaders.h"
#include "dkim.h"
#include "dkimsignature.h"

typedef struct DkimDigester DkimDigester;

extern DkimStatus DkimDigester_new(DkimHashAlgorithm digest_alg,
                                   DkimKeyType pubkey_alg, DkimC14nAlgorithm header_canon_alg,
                                   DkimC14nAlgorithm body_canon_alg, long long body_length_limit,
                                   bool keep_leading_header_space, DkimDigester **digester);
extern DkimStatus DkimDigester_newWithSignature(const DkimSignature *signature,
                                                bool keep_leading_header_space,
                                                DkimDigester **digester);
extern void DkimDigester_free(DkimDigester *self);
extern DkimStatus DkimDigester_updateBody(DkimDigester *self, const unsigned char *buf, size_t len);
extern DkimStatus DkimDigester_verifyMessage(DkimDigester *self, const InetMailHeaders *headers,
                                             const DkimSignature *signature, EVP_PKEY *pkey);
extern DkimStatus DkimDigester_signMessage(DkimDigester *self, const InetMailHeaders *headers,
                                           DkimSignature *signature, EVP_PKEY *pkey);
extern DkimStatus DkimDigester_enableC14nDump(DkimDigester *self, const char *fnHeaderDump,
                                              const char *fnBodyDump);

#endif /* __DKIM_DIGESTER_H__ */
