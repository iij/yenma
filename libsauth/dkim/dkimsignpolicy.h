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

#ifndef __DKIM_SIGN_POLICY_H__
#define __DKIM_SIGN_POLICY_H__

#include <stdbool.h>
#include "dkimenum.h"

#ifdef __cplusplus
extern "C" {
#endif

struct DkimSignPolicy {
    // TTL (sec) of generated DKIM signature.
    // If negative value is set, sig-x-tag doesn't added to the generating DKIM signatures.
    long long signature_ttl;
    // digest algorithm
    DkimHashAlgorithm hashalg;
    // encryption algorithm of public key cryptosystem
    DkimKeyType keytype;
    // canonicalization algorithm for header part
    DkimC14nAlgorithm canon_method_header;
    // canonicalization algorithm for body part
    DkimC14nAlgorithm canon_method_body;
    // use CRLF as end-on-line character for DKIM-Signature headers to be generated
    bool sign_header_with_crlf;
    // digest algorithm for DKIM-ATPS
    DkimHashAlgorithm atps_hashalg;
};

#ifdef __cplusplus
}
#endif

#endif /* __DKIM_SIGN_POLICY_H__ */
