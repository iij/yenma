/*
 * Copyright (c) 2018 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifndef __OPENSSL_EVP_COMPAT_H__
#define __OPENSSL_EVP_COMPAT_H__

#include <openssl/evp.h>

#if OPENSSL_VERSION_NUMBER < 0x10000000L

// OpenSSL 1.0 introduces EVP_PKEY accessors
inline int EVP_PKEY_base_id(const EVP_PKEY *pkey) {
    return EVP_PKEY_type(pkey->type);
}
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L

// OpenSSL 1.1 renames EVP_MD_CTX_{create,destroy} to EVP_MD_CTX_{new,free}
#define EVP_MD_CTX_new() EVP_MD_CTX_create()
#define EVP_MD_CTX_free(__ctx) EVP_MD_CTX_destroy((__ctx))

#else

// ERR_remove_state is deprecated
#define ERR_remove_state(__pid)

#endif

#endif /* __OPENSSL_EVP_COMPAT_H__ */
