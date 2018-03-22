#ifndef OPENSSL_EVP_COMPAT_H

#include <openssl/evp.h>

#if OPENSSL_VERSION_NUMBER < 0x10000000L
/* OpenSSL 1.0 introduces EVP_PKEY accessors */

static inline int EVP_PKEY_id(const EVP_PKEY *pkey) {
    return pkey->type;
}

static inline int EVP_PKEY_base_id(const EVP_PKEY *pkey) {
    return EVP_PKEY_type(pkey->type);
}
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
/* OpenSSL 1.1 renames EVP_MD_CTX_{create,destroy} to EVP_MD_CTX_{new,free} */

#define EVP_MD_CTX_new() EVP_MD_CTX_create()
#define EVP_MD_CTX_free(ctx) EVP_MD_CTX_destroy((ctx))
#endif

#endif /* OPENSSL_EVP_COMPAT_H */
