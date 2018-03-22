/*
 * Copyright (c) 2006-2018 Internet Initiative Japan Inc. All rights reserved.
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
#include <stdbool.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/x509.h>

#include "loghandler.h"
#include "dkimlogger.h"
#include "stdaux.h"
#include "ptrop.h"
#include "xbuffer.h"
#include "xskip.h"
#include "xparse.h"
#include "pstring.h"
#include "intarray.h"
#include "inetdomain.h"
#include "inetmailbox.h"
#include "openssl-evp-compat.h"
#include "dnsresolv.h"
#include "dkim.h"
#include "dkimspec.h"
#include "dkimenum.h"
#include "dkimwildcard.h"
#include "dkimtaglistobject.h"
#include "dkimverificationpolicy.h"
#include "dkimconverter.h"
#include "dkimsignature.h"
#include "dkimpublickey.h"

// a limit number of records to try to check where it is valid as DKIM public key record
#define DKIM_PUBKEY_CANDIDATE_MAX   10

struct DkimPublicKey {
    DkimTagListObject_MEMBER;
    const DkimVerificationPolicy *policy;
    DkimHashAlgorithm hashalg;  // key-h-tag
    DkimKeyType keytype;        // key-k-tag
    DkimServiceType service_type;   // key-s-tag
    DkimSelectorFlag selector_flag; // key-t-tag
    EVP_PKEY *pkey;             // key-p-tag
    char *granularity;          // key-g-tag
};

static DkimStatus DkimPublicKey_parse_v(DkimTagListObject *base,
                                        const DkimTagParseContext *context, const char **nextp);
static DkimStatus DkimPublicKey_parse_g(DkimTagListObject *base,
                                        const DkimTagParseContext *context, const char **nextp);
static DkimStatus DkimPublicKey_parse_h(DkimTagListObject *base,
                                        const DkimTagParseContext *context, const char **nextp);
static DkimStatus DkimPublicKey_parse_k(DkimTagListObject *base,
                                        const DkimTagParseContext *context, const char **nextp);
static DkimStatus DkimPublicKey_parse_p(DkimTagListObject *base,
                                        const DkimTagParseContext *context, const char **nextp);
static DkimStatus DkimPublicKey_parse_s(DkimTagListObject *base,
                                        const DkimTagParseContext *context, const char **nextp);
static DkimStatus DkimPublicKey_parse_t(DkimTagListObject *base,
                                        const DkimTagParseContext *context, const char **nextp);

// parsing function table of DkimPublicKey object
static const DkimTagListObjectFieldMap dkim_pubkey_field_table[] = {
    {"v", DkimPublicKey_parse_v, false, DKIM1_VERSION_TAG},
    {"g", DkimPublicKey_parse_g, false, "*"},
    /*
     * Though default semantics for absence of key-h-tag is "allowing all algorithms",
     * this semantics like "*" is not defined in RFC6376.
     * So I enumerated all of acceptable hash algorithms as default value as below.
     */
    {"h", DkimPublicKey_parse_h, false, "sha1:sha256"},
    {"k", DkimPublicKey_parse_k, false, "rsa"},
    {"n", NULL, false, NULL},
    {"p", DkimPublicKey_parse_p, true, NULL},
    {"s", DkimPublicKey_parse_s, false, "*"},
    {"t", DkimPublicKey_parse_t, false, NULL},
    {NULL, NULL, false, NULL},  // sentinel
};

////////////////////////////////////////////////////////////////////////
// private functions

/*
 * [RFC6376] 3.6.1.
 * key-v-tag    = %x76 [FWS] "=" [FWS] %x44.4B.49.4D.31
 */
DkimStatus
DkimPublicKey_parse_v(DkimTagListObject *base __attribute__((unused)),
                      const DkimTagParseContext *context, const char **nextp)
{
    /*
     * appearance at the head of record (0 == context->tag_no)
     * or set as default value (DKIM_TAGLISTOBJECT_TAG_NO_DEFAULT_VALUE == context->tag_no) are accepted.
     * error otherwise.
     */
    if (DKIM_TAGLISTOBJECT_TAG_NO_AS_DEFAULT_VALUE != context->tag_no && 0 < context->tag_no) {
        *nextp = context->value_head;
        DkimLogPermFail("key-v-tag appeared not at the front of public key record: near %.50s",
                        context->value_head);
        return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
    }   // end if

    // compare "DKIM1" tag case-sensitively
    if (0 < XSkip_string(context->value_head, context->value_tail, DKIM1_VERSION_TAG, nextp)) {
        return DSTAT_OK;
    } else {
        *nextp = context->value_head;
        DkimLogPermFail("unsupported public key version tag: near %.50s", context->value_head);
        return DSTAT_PERMFAIL_INCOMPATIBLE_KEY_VERSION;
    }   // end if
}   // end function: DkimPublicKey_parse_v

/*
 * [RFC4871] 3.6.1.
 * key-g-tag       = %x67 [FWS] "=" [FWS] key-g-tag-lpart
 * key-g-tag-lpart = [dot-atom-text] ["*" [dot-atom-text] ]
 */
DkimStatus
DkimPublicKey_parse_g(DkimTagListObject *base, const DkimTagParseContext *context,
                      const char **nextp)
{
    DkimPublicKey *self = (DkimPublicKey *) base;

    if (!self->policy->rfc4871_compatible) {
        // key-g-tag is obsoleted by RFC6376, so we just ignore this tag.
        *nextp = context->value_tail;
        return DSTAT_OK;
    }   // end if

    // RFC4871 compatible mode
    if (NULL != self->granularity) {
        DkimLogImplError("key-g-tag already set");
        return DSTAT_SYSERR_IMPLERROR;
    }   // end if

    // '*' is included in dot-atom-text.
    // ignore return value of XSkip_looseDotAtomText(), because 0-length of key-g-tag value is valid.
    (void) XSkip_looseDotAtomText(context->value_head, context->value_tail, nextp);
    self->granularity = strpdup(context->value_head, *nextp);
    if (NULL == self->granularity) {
        LogNoResource();
        return DSTAT_SYSERR_NORESOURCE;
    }   // end if

    return DSTAT_OK;
}   // end function: DkimPublicKey_parse_g

/*
 * [RFC6376] 3.6.1.
 * key-h-tag       = %x68 [FWS] "=" [FWS] key-h-tag-alg
 *                   *( [FWS] ":" [FWS] key-h-tag-alg )
 * key-h-tag-alg   = "sha1" / "sha256" / x-key-h-tag-alg
 * x-key-h-tag-alg = hyphenated-word   ; for future extension
 */
DkimStatus
DkimPublicKey_parse_h(DkimTagListObject *base, const DkimTagParseContext *context,
                      const char **nextp)
{
    const char *p = context->value_head;
    const char *algtail;
    DkimPublicKey *self = (DkimPublicKey *) base;

    self->hashalg = DKIM_HASH_ALGORITHM_NULL;
    *nextp = context->value_head;
    do {
        (void) XSkip_fws(p, context->value_tail, &p);
        if (0 >= XSkip_hyphenatedWord(p, context->value_tail, &algtail)) {
            // value of key-h-tag doesn't match hyphenated-word
            DkimLogPermFail("key-h-tag has no valid digest algorithm: near %.50s",
                            context->value_head);
            return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
        }   // end if

        DkimHashAlgorithm digestalg = DkimEnum_lookupHashAlgorithmByNameSlice(p, algtail);
        // SPEC: ignore unknown keyword of key-h-tag-alg in view of future extension
        // SPEC: take no notice of multiple times occurrence of same keyword of key-h-tag-alg
        if (DKIM_HASH_ALGORITHM_NULL != digestalg) {
            self->hashalg |= digestalg;
        }   // end if

        *nextp = algtail;   // key-h-tag ends at this timing if no more ':' is left
        XSkip_fws(algtail, context->value_tail, &p);
    } while (0 < XSkip_char(p, context->value_tail, ':', &p));
    return DSTAT_OK;
}   // end function: DkimPublicKey_parse_h

/*
 * [RFC6376] 3.6.1.
 * key-k-tag        = %x76 [FWS] "=" [FWS] key-k-tag-type
 * key-k-tag-type   = "rsa" / x-key-k-tag-type
 * x-key-k-tag-type = hyphenated-word   ; for future extension
 */
DkimStatus
DkimPublicKey_parse_k(DkimTagListObject *base, const DkimTagParseContext *context,
                      const char **nextp)
{
    DkimPublicKey *self = (DkimPublicKey *) base;
    self->keytype = DkimEnum_lookupKeyTypeByNameSlice(context->value_head, context->value_tail);
    if (DKIM_KEY_TYPE_NULL != self->keytype) {
        *nextp = context->value_tail;
        return DSTAT_OK;
    } else {
        *nextp = context->value_head;
        DkimLogPermFail("unsupported public key algorithm: near %.50s", context->value_head);
        return DSTAT_PERMFAIL_UNSUPPORTED_KEY_ALGORITHM;
    }   // end if
}   // end function: DkimPublicKey_parse_k

/*
 * [RFC6376] 3.6.1.
 * key-n-tag    = %x6e [FWS] "=" [FWS] qp-section
 *
 * Ignore key-n-tag entirely.
 * This tag has no concern with verification process.
 */

/*
 * [RFC6376]
 * key-p-tag    = %x70 [FWS] "=" [ [FWS] base64string]
 */
DkimStatus
DkimPublicKey_parse_p(DkimTagListObject *base, const DkimTagParseContext *context,
                      const char **nextp)
{
    DkimPublicKey *self = (DkimPublicKey *) base;
    const char *p = context->value_head;

    SETDEREF(nextp, context->value_head);
    XSkip_fws(p, context->value_tail, &p);
    if (context->value_tail <= p) {
        // public key has revoked
        DkimLogPermFail("public key has revoked");
        return DSTAT_PERMFAIL_KEY_REVOKED;
    }   // end if

    DkimStatus decode_stat;
    XBuffer *rawpubkey = DkimConverter_decodeBase64(p, context->value_tail, &p, &decode_stat);
    if (NULL == rawpubkey) {
        return decode_stat;
    }   // end if

    const unsigned char *pbuf = XBuffer_getBytes(rawpubkey);
    size_t psize = XBuffer_getSize(rawpubkey);

    // ATTENTION: second parameter of d2i_PUBKEY() may be overwritten (!?)
    self->pkey = d2i_PUBKEY(NULL, &pbuf, psize);
    XBuffer_free(rawpubkey);
    if (NULL == self->pkey) {
        DkimLogPermFail("key-p-tag doesn't valid public key record: record=%s",
                        context->value_head);
        return DSTAT_PERMFAIL_PUBLICKEY_BROKEN;
    }   // end if

    SETDEREF(nextp, p);
    return DSTAT_OK;
}   // end function: DkimPublicKey_parse_p

/*
 * [RFC6376] 3.6.1.
 * key-s-tag        = %x73 [FWS] "=" [FWS] key-s-tag-type
 *                    *( [FWS] ":" [FWS] key-s-tag-type )
 * key-s-tag-type   = "email" / "*" / x-key-s-tag-type
 * x-key-s-tag-type = hyphenated-word   ; for future extension
 */
DkimStatus
DkimPublicKey_parse_s(DkimTagListObject *base, const DkimTagParseContext *context,
                      const char **nextp)
{
    DkimPublicKey *self = (DkimPublicKey *) base;
    const char *p = context->value_head;

    self->service_type = DKIM_SERVICE_TYPE_NULL;
    *nextp = context->value_head;
    do {
        XSkip_fws(p, context->value_tail, &p);
        // be careful that '*' is not included in hyphenated-word
        const char *srvtail;
        if (0 >= XSkip_hyphenatedWord(p, context->value_tail, &srvtail)
            && 0 >= XSkip_char(p, context->value_tail, '*', &srvtail)) {
            // value of key-s-tag doesn't match hyphenated-word or '*'
            DkimLogPermFail("key-s-tag includes invalid service type: near %.50s",
                            context->value_head);
            return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
        }   // end if

        DkimServiceType service_type = DkimEnum_lookupServiceTypeByNameSlice(p, srvtail);
        // SPEC: ignore unknown keyword of key-s-tag-type in view of future extension
        // SPEC: take no notice of multiple times occurrence of same keyword of key-s-tag-type
        if (DKIM_SERVICE_TYPE_NULL != service_type) {
            self->service_type |= service_type;
        }   // end if

        *nextp = srvtail;   // key-s-tag ends at this timing if no more ':' is left
        XSkip_fws(srvtail, context->value_tail, &p);
    } while (0 < XSkip_char(p, context->value_tail, ':', &p));
    return DSTAT_OK;
}   // end function: DkimPublicKey_parse_s

/*
 * [RFC6376] 3.6.1.
 * key-t-tag        = %x74 [FWS] "=" [FWS] key-t-tag-flag
 *                    *( [FWS] ":" [FWS] key-t-tag-flag )
 * key-t-tag-flag   = "y" / "s" / x-key-t-tag-flag
 * x-key-t-tag-flag = hyphenated-word   ; for future extension
 */
DkimStatus
DkimPublicKey_parse_t(DkimTagListObject *base, const DkimTagParseContext *context,
                      const char **nextp)
{
    DkimPublicKey *self = (DkimPublicKey *) base;
    const char *p = context->value_head;

    self->selector_flag = DKIM_SELECTOR_FLAG_NULL;
    *nextp = context->value_head;
    do {
        XSkip_fws(p, context->value_tail, &p);
        const char *wordtail;
        if (0 >= XSkip_hyphenatedWord(p, context->value_tail, &wordtail)) {
            // value of key-t-tag doesn't match hyphenated-word or '*'
            DkimLogPermFail("key-t-tag flag includes invalid value: near %.50s",
                            context->value_head);
            return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
        }   // end if

        DkimSelectorFlag selector_flag = DkimEnum_lookupSelectorFlagByNameSlice(p, wordtail);
        // SPEC: ignore unknown keyword of key-t-tag-flag in view of future extension
        // SPEC: take no notice of multiple times occurrence of same keyword of key-t-tag-flag
        if (DKIM_SELECTOR_FLAG_NULL != selector_flag) {
            self->selector_flag |= selector_flag;
        }   // end if

        *nextp = wordtail;  // key-t-tag ends at this timing if no more ':' is left
        XSkip_fws(wordtail, context->value_tail, &p);
    } while (0 < XSkip_char(p, context->value_tail, ':', &p));
    return DSTAT_OK;
}   // end function: DkimPublicKey_parse_t

////////////////////////////////////////////////////////////////////////
// public functions

/**
 * build DkimPublicKey object from string
 * @error DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION tag-value syntax violation
 * @error DSTAT_PERMFAIL_MISSING_REQUIRED_TAG missing required tag
 * @error DSTAT_PERMFAIL_TAG_DUPLICATED multiple identical tags are found
 * @error DSTAT_SYSERR_IMPLERROR obvious implementation error
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 * @error DSTAT_PERMFAIL_INCOMPATIBLE_KEY_VERSION unsupported public key version
 * @error DSTAT_PERMFAIL_UNSUPPORTED_KEY_ALGORITHM unsupported public key algorithm
 * @error DSTAT_PERMFAIL_KEY_REVOKED Public key record has revoked
 * @error DSTAT_PERMFAIL_PUBLICKEY_BROKEN Public key is broken (returned by OpenSSL d2i_PUBKEY())
 * @error DSTAT_PERMFAIL_PUBLICKEY_TYPE_MISMATCH key-k-tag and the content of public key (key-p-tag) does not matched
 */
DkimStatus
DkimPublicKey_build(const DkimVerificationPolicy *policy, const char *keyval, const char *domain,
                    DkimPublicKey **publickey)
{
    DkimPublicKey *self = (DkimPublicKey *) malloc(sizeof(DkimPublicKey));
    if (NULL == self) {
        LogNoResource();
        return DSTAT_SYSERR_NORESOURCE;
    }   // end if
    memset(self, 0, sizeof(DkimPublicKey));
    self->ftbl = dkim_pubkey_field_table;
    self->policy = policy;

    DkimStatus build_stat =
        DkimTagListObject_build((DkimTagListObject *) self, keyval, STRTAIL(keyval), false, false);
    if (DSTAT_OK != build_stat) {
        if (DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION == build_stat) {
            build_stat = DSTAT_PERMFAIL_KEY_SYNTAX_VIOLATION;
        }   // end if
        DkimLogPermFail("invalid public key record: domain=%s", domain);
        DkimPublicKey_free(self);
        return build_stat;
    }   // end if

    // compare key type key-k-tag declared and stored in key-p-tag
    switch (self->keytype) {
    case DKIM_KEY_TYPE_RSA:
        if (EVP_PKEY_RSA != EVP_PKEY_base_id(self->pkey)) {
            DkimLogPermFail
                ("key-k-tag and key-p-tag doesn't match: domain=%s, keyalg=0x%x, keytype=0x%x",
                 domain, self->keytype, EVP_PKEY_base_id(self->pkey));
            DkimPublicKey_free(self);
            return DSTAT_PERMFAIL_PUBLICKEY_TYPE_MISMATCH;
        }   // end if
        break;
#if defined(EVP_PKEY_ED25519)
    case DKIM_KEY_TYPE_ED25519:
        if (EVP_PKEY_ED25519 != EVP_PKEY_base_id(self->pkey) {
            DkimLogPermFail
                ("key-k-tag and key-p-tag doesn't match: domain=%s, keyalg=0x%x, keytype=0x%x",
                 domain, self->keytype, EVP_PKEY_base_id(self->pkey));
            DkimPublicKey_free(self);
            return DSTAT_PERMFAIL_PUBLICKEY_TYPE_MISMATCH;
        }   // end if
        break;
#endif
    default:
        DkimLogImplError("unexpected public key algorithm: pubkeyalg=0x%x", self->keytype);
        DkimPublicKey_free(self);
        return DSTAT_SYSERR_IMPLERROR;
    }   // end switch

    *publickey = self;
    return DSTAT_OK;
}   // end function: DkimPublicKey_build

/**
 * release DkimPublicKey object
 * @param self DkimPublicKey object to release
 */
void
DkimPublicKey_free(DkimPublicKey *self)
{
    if (NULL == self) {
        return;
    }   // end if

    free(self->granularity);
    if (NULL != self->pkey) {
        EVP_PKEY_free(self->pkey);
    }   // end if
    free(self);
}   // end function: DkimPublicKey_free

static bool
DkimPublicKey_isDigestAlgMatched(const DkimPublicKey *self, DkimHashAlgorithm digestalg)
{
    return bool_cast((self->hashalg) & digestalg);
}   // end function: DkimPublicKey_isDigestAlgMatched

static bool
DkimPublicKey_isPubKeyAlgMatched(const DkimPublicKey *self, DkimKeyType pubkeyalg)
{
    return self->keytype == pubkeyalg;
}   // end function: DkimPublicKey_isPubKeyAlgMatched

/**
 * validate if retrieved key is suitable for the signature.
 * @attention public key intended not to used for "email" as service type is rejected.
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_PERMFAIL_INAPPROPRIATE_SERVICE_TYPE service type dose not allow the public key record to be applied to email
 * @error DSTAT_PERMFAIL_INAPPROPRIATE_HASH_ALGORITHM digest algorithm of the public key record (key-h-tag) does not match the one of the signature (sig-a-tag-h)
 * @error DSTAT_PERMFAIL_INAPPROPRIATE_KEY_ALGORITHM public key algorithm of the public key record (key-k-tag) does not match the one of the signature (sig-a-tag-k)
 * @error DSTAT_PERMFAIL_PUBLICKEY_SUBDOMAIN_PROHIBITED public key record does not accept subdomain
 * @error DSTAT_PERMFAIL_INAPPLICABLE_KEY the local-part of "i=" tag of the signature (sig-i-tag) does not match the granularity of the public key record (key-g-tag)
 */
static DkimStatus
DkimPublicKey_validate(DkimPublicKey *self, const char *record, const DkimSignature *signature)
{
    // check service type.
    // reject if "email" is not listed.
    if (!DkimPublicKey_isEMailServiceUsable(self)) {
        DkimLogPermFail("omitting public key record for service type mismatch: pubkey=%s", record);
        return DSTAT_PERMFAIL_INAPPROPRIATE_SERVICE_TYPE;
    }   // end if

    /*
     * compare digest algorithm used in signature (sig-a-tag-h) and listed in public key (key-h-tag)
     * [RFC6376] 6.1.2.
     * 6.  If the "h=" tag exists in the public-key record and the hash
     *     algorithm implied by the "a=" tag in the DKIM-Signature header
     *     field is not included in the contents of the "h=" tag, the
     *     Verifier MUST ignore the key record and return PERMFAIL
     *     (inappropriate hash algorithm).
     */
    if (!DkimPublicKey_isDigestAlgMatched(self, DkimSignature_getHashAlgorithm(signature))) {
        DkimLogPermFail
            ("omitting public key record for digest algorithm mismatch: digestalg=%s, pubkey=%s",
             DkimEnum_lookupHashAlgorithmByValue(DkimSignature_getHashAlgorithm(signature)),
             record);
        return DSTAT_PERMFAIL_INAPPROPRIATE_HASH_ALGORITHM;
    }   // end if

    /*
     * compare public key algorithm used in signature (sig-a-tag-k) and listed in public key (key-k-tag)
     * [RFC6376] 6.1.2.
     * 8.  If the public-key data is not suitable for use with the algorithm
     *     and key types defined by the "a=" and "k=" tags in the DKIM-
     *     Signature header field, the Verifier MUST immediately return
     *     PERMFAIL (inappropriate key algorithm).
     */
    if (!DkimPublicKey_isPubKeyAlgMatched(self, DkimSignature_getKeyType(signature))) {
        DkimLogPermFail
            ("omitting public key record for public key algorithm mismatch: pubkeyalg=%s, pubkey=%s",
             DkimEnum_lookupKeyTypeByValue(DkimSignature_getKeyType(signature)), record);
        return DSTAT_PERMFAIL_INAPPROPRIATE_KEY_ALGORITHM;
    }   // end if

    /*
     * Check if public key permits subdomain.
     * It is confirmed that domain of AUID is the same as or a subdomain of SDID in DkimSignature_validate().
     * [RFC6376] 3.10.
     * If the referenced key record
     * contains the "s" flag as part of the "t=" tag, the domain of the AUID
     * ("i=" flag) MUST be the same as that of the SDID (d=) domain.  If
     * this flag is absent, the domain of the AUID MUST be the same as, or a
     * subdomain of, the SDID.
     */
    const InetMailbox *auid = DkimSignature_getAuid(signature);
    if (DkimPublicKey_isSubdomainProhibited(self)) {
        // If "s" flag is listed in key-t-tag, check if domain of AUID is the same as SDID.
        // subdomain is not permitted.
        if (!InetDomain_equals(DkimSignature_getSdid(signature), InetMailbox_getDomain(auid))) {
            DkimLogPermFail
                ("omitting public key record for subdomain prohibition: AUID-Domain=%s, SDID=%s",
                 InetMailbox_getDomain(auid), DkimSignature_getSdid(signature));
            return DSTAT_PERMFAIL_PUBLICKEY_SUBDOMAIN_PROHIBITED;
        }   // end if
    }   // end if

    if (self->policy->rfc4871_compatible) {
        /*
         * compare key-g-tag and localpart of AUID
         *
         * [RFC4871] 6.1.2.
         * 6.  If the "g=" tag in the public key does not match the Local-part
         *     of the "i=" tag in the message signature header field, the
         *     verifier MUST ignore the key record and return PERMFAIL
         *     (inapplicable key).  If the Local-part of the "i=" tag on the
         *     message signature is not present, the "g=" tag must be "*" (valid
         *     for all addresses in the domain) or the entire g= tag must be
         *     omitted (which defaults to "g=*"), otherwise the verifier MUST
         *     ignore the key record and return PERMFAIL (inapplicable key).
         *     Other than this test, verifiers SHOULD NOT treat a message signed
         *     with a key record having a "g=" tag any differently than one
         *     without; in particular, verifiers SHOULD NOT prefer messages that
         *     seem to have an individual signature by virtue of a "g=" tag
         *     versus a domain signature.
         */
        const char *granularity = DkimPublicKey_getGranularity(self);
        const char *localpart = InetMailbox_getLocalPart(auid);
        if (!DkimWildcard_matchPubkeyGranularity
            (granularity, STRTAIL(granularity), localpart, STRTAIL(localpart))) {
            DkimLogPermFail
                ("omitting public key record for granularity mismatch: AUID-localpart=%s, granularity=%s",
                 localpart, granularity);
            return DSTAT_PERMFAIL_INAPPLICABLE_KEY;
        }   // end if
    }   // end if

    return DSTAT_OK;
}   // end function: DkimPublicKey_validate

/**
 * @attention public key intended not to used for "email" as service type is rejected.
 * @error DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION tag-value syntax violation
 * @error DSTAT_PERMFAIL_MISSING_REQUIRED_TAG missing required tag
 * @error DSTAT_PERMFAIL_TAG_DUPLICATED multiple identical tags are found
 * @error DSTAT_SYSERR_IMPLERROR obvious implementation error
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 * @error DSTAT_PERMFAIL_INCOMPATIBLE_KEY_VERSION unsupported public key version
 * @error DSTAT_PERMFAIL_UNSUPPORTED_KEY_ALGORITHM unsupported public key algorithm
 * @error DSTAT_PERMFAIL_KEY_REVOKED Public key record has revoked
 * @error DSTAT_PERMFAIL_PUBLICKEY_BROKEN Public key is broken (returned by OpenSSL d2i_PUBKEY())
 * @error DSTAT_PERMFAIL_PUBLICKEY_TYPE_MISMATCH key-k-tag and the content of public key (key-p-tag) does not matched
 * @error DSTAT_PERMFAIL_INAPPROPRIATE_SERVICE_TYPE service type dose not allow the public key record to be applied to email
 * @error DSTAT_PERMFAIL_INAPPROPRIATE_HASH_ALGORITHM digest algorithm of the public key record (key-h-tag) does not match the one of the signature (sig-a-tag-h)
 * @error DSTAT_PERMFAIL_INAPPROPRIATE_KEY_ALGORITHM public key algorithm of the public key record (key-k-tag) does not match the one of the signature (sig-a-tag-k)
 * @error DSTAT_PERMFAIL_PUBLICKEY_SUBDOMAIN_PROHIBITED public key record does not accept subdomain
 * @error DSTAT_PERMFAIL_INAPPLICABLE_KEY the local-part of "i=" tag of the signature (sig-i-tag) does not match the granularity of the public key record (key-g-tag)
 */
static DkimStatus
DkimPublicKey_ensure(const DkimVerificationPolicy *policy, const char *record,
                     const char *dkimdomain, const DkimSignature *signature,
                     DkimPublicKey **publickey)
{
    assert(NULL != record);
    assert(NULL != dkimdomain);
    assert(NULL != signature);
    assert(NULL != publickey);

    DkimPublicKey *self = NULL;
    DkimStatus dstat = DkimPublicKey_build(policy, record, dkimdomain, &self);
    if (DSTAT_OK != dstat) {
        return dstat;
    }   // end if

    // validate public key
    DkimStatus validate_stat = DkimPublicKey_validate(self, record, signature);
    if (DSTAT_OK != validate_stat) {
        DkimPublicKey_free(self);
        return validate_stat;
    }   // end if

    *publickey = self;
    return DSTAT_OK;
}   // end function: DkimPublicKey_ensure

/**
 * @attention The returned string should be released with free() when no longer needed.
 */
static DkimStatus
DkimPublicKey_buildQname(const DkimSignature *signature, char **qname)
{
    assert(NULL != signature);
    assert(NULL != qname);

    /*
     * [RFC6376] 3.6.2.1.
     * All DKIM keys are stored in a subdomain named "_domainkey".  Given a
     * DKIM-Signature field with a "d=" tag of "example.com" and an "s=" tag
     * of "foo.bar", the DNS query will be for
     * "foo.bar._domainkey.example.com".
     */

    const char *domain = DkimSignature_getSdid(signature);
    const char *selector = DkimSignature_getSelector(signature);

    // memory allocation
    size_t buflen = strlen(selector) + sizeof("." DKIM_DNS_NAMESPACE ".") + strlen(domain);
    char *buf = (char *) malloc(buflen);
    if (NULL == buf) {
        LogNoResource();
        return DSTAT_SYSERR_NORESOURCE;
    }   // end if

    // build domain name public keys should be stored in
    if ((int) buflen <= snprintf(buf, buflen, "%s." DKIM_DNS_NAMESPACE ".%s", selector, domain)) {
        DkimLogImplError("allocated memory too small");
        free(buf);
        return DSTAT_SYSERR_IMPLERROR;
    }   // end if

    *qname = buf;
    return DSTAT_OK;
}   // end function: DkimPublicKey_buildQname

/**
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 * @error DSTAT_SYSERR_IMPLERROR obvious implementation error
 * @error DSTAT_PERMFAIL_NO_KEY_FOR_SIGNATURE Public key record does not exist
 * @error DSTAT_TMPERR_DNS_ERROR_RESPONSE DNS lookup error (received error response)
 * @error DSTAT_SYSERR_DNS_LOOKUP_FAILURE DNS lookup error (failed to lookup itself)
 */
static DkimStatus
DkimPublicKey_retrieve(const DkimVerificationPolicy *policy, const DkimSignature *signature,
                       DnsResolver *resolver, DkimPublicKey **publickey)
{
    assert(NULL != signature);
    assert(NULL != resolver);
    assert(NULL != publickey);

    char *qname = NULL;
    DkimStatus build_stat = DkimPublicKey_buildQname(signature, &qname);
    if (DSTAT_OK != build_stat) {
        return build_stat;
    }   // end if

    DnsTxtResponse *txt_rr = NULL;
    dns_stat_t txtquery_stat = DnsResolver_lookupTxt(resolver, qname, &txt_rr);
    switch (txtquery_stat) {
    case DNS_STAT_NOERROR:;
        /*
         * [RFC6376] 3.6.2.2.
         * TXT RRs MUST be unique for a particular
         * selector name; that is, if there are multiple records in an RRset,
         * the results are undefined.
         *
         * [RFC6376] 6.1.2.
         * 4.  If the query for the public key returns multiple key records, the
         *     Verifier can choose one of the key records or may cycle through
         *     the key records, performing the remainder of these steps on each
         *     record at the discretion of the implementer.  The order of the
         *     key records is unspecified.  If the Verifier chooses to cycle
         *     through the key records, then the "return ..." wording in the
         *     remainder of this section means "try the next key record, if any;
         *     if none, return to try another signature in the usual way".
         */
        int recnum = MIN(txt_rr->num, DKIM_PUBKEY_CANDIDATE_MAX);   // limit the number of RRs to prevent DoS attack
        for (int i = 0; i < recnum; ++i) {
            DkimPublicKey *self = NULL;
            DkimStatus pubkey_dstat =
                DkimPublicKey_ensure(policy, txt_rr->data[i], qname, signature,
                                     &self);
            if (DSTAT_OK == pubkey_dstat) {
                // valid as public key record
                DnsTxtResponse_free(txt_rr);
                free(qname);
                *publickey = self;
                return DSTAT_OK;    // successful completion
            } else if (DSTAT_ISCRITERR(pubkey_dstat)) {
                // propagate system errors as-is
                DkimLogSysError
                    ("System error occurred while parsing public key: domain=%s, error=%s, record=%s",
                     qname, DkimStatus_getSymbol(pubkey_dstat), NNSTR(txt_rr->data[i]));
                DnsTxtResponse_free(txt_rr);
                free(qname);
                return pubkey_dstat;
            } else if (DSTAT_ISPERMFAIL(pubkey_dstat)) {
                /*
                 * discard invalid public key record candidate
                 * [RFC6376] 6.1.2.
                 * The Verifier MUST validate the key record and MUST
                 * ignore any public-key records that are malformed.
                 */
                LogDebug("public key candidate discarded: domain=%s, error=%s, record=%s",
                         qname, DkimStatus_getSymbol(pubkey_dstat), NNSTR(txt_rr->data[i]));
            }   // end if
        }   // end for
        // no valid public key record is found
        DnsTxtResponse_free(txt_rr);
        DkimLogPermFail("No suitable public key record found from DNS: domain=%s", qname);
        free(qname);
        return DSTAT_PERMFAIL_NO_KEY_FOR_SIGNATURE;

    case DNS_STAT_NXDOMAIN:
    case DNS_STAT_NODATA:
    case DNS_STAT_NOVALIDANSWER:
        /*
         * [RFC6376] 6.1.2.
         * 3.  If the query for the public key fails because the corresponding
         *     key record does not exist, the Verifier MUST immediately return
         *     PERMFAIL (no key for signature).
         */
        DkimLogPermFail("No public key record is found on DNS: qname=%s, error=%s",
                        qname, DnsResolver_getErrorSymbol(resolver));
        free(qname);
        return DSTAT_PERMFAIL_NO_KEY_FOR_SIGNATURE;

    case DNS_STAT_FORMERR:
    case DNS_STAT_SERVFAIL:
    case DNS_STAT_NOTIMPL:
    case DNS_STAT_REFUSED:
    case DNS_STAT_YXDOMAIN:
    case DNS_STAT_YXRRSET:
    case DNS_STAT_NXRRSET:
    case DNS_STAT_NOTAUTH:
    case DNS_STAT_NOTZONE:
    case DNS_STAT_RESERVED11:
    case DNS_STAT_RESERVED12:
    case DNS_STAT_RESERVED13:
    case DNS_STAT_RESERVED14:
    case DNS_STAT_RESERVED15:
    case DNS_STAT_RESOLVER:
    case DNS_STAT_RESOLVER_INTERNAL:
        /*
         * [RFC6376] 6.1.2.
         * 2.  If the query for the public key fails to respond, the Verifier
         *     MAY seek a later verification attempt by returning TEMPFAIL (key
         *     unavailable).
         */
        LogDnsError("txt", qname, "DKIM public key record", DnsResolver_getErrorSymbol(resolver));
        free(qname);
        return DSTAT_TMPERR_DNS_ERROR_RESPONSE;

    case DNS_STAT_SYSTEM:
        DkimLogSysError("System error occurred on DNS lookup: rrtype=txt, qname=%s, error=%s",
                        qname, DnsResolver_getErrorSymbol(resolver));
        free(qname);
        return DSTAT_SYSERR_DNS_LOOKUP_FAILURE;

    case DNS_STAT_NOMEMORY:
        LogNoResource();
        free(qname);
        return DSTAT_SYSERR_NORESOURCE;

    case DNS_STAT_BADREQUEST:
    default:
        DkimLogImplError
            ("DnsResolver_lookupTxt returns unexpected value: value=0x%x, rrtype=txt, qname=%s",
             txtquery_stat, qname);
        free(qname);
        return DSTAT_SYSERR_IMPLERROR;
    }   // end switch
}   // end function: DkimPublicKey_retrieve

/**
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 * @error DSTAT_SYSERR_IMPLERROR obvious implementation error
 * @error DSTAT_PERMFAIL_NO_KEY_FOR_SIGNATURE Public key record does not exist
 * @error DSTAT_TMPERR_DNS_ERROR_RESPONSE DNS lookup error (received error response)
 * @error DSTAT_SYSERR_DNS_LOOKUP_FAILURE DNS lookup error (failed to lookup itself)
 */
static DkimStatus
DkimPublicKey_lookupImpl(const DkimVerificationPolicy *policy, const DkimSignature *signature,
                         DnsResolver *resolver, DkimPublicKey **publickey)
{
    /*
     * [RFC6376] 3.5.
     * If there are multiple query mechanisms listed, the choice of query
     * mechanism MUST NOT change the interpretation of the signature.
     * Implementations MUST use the recognized query mechanisms in the
     * order presented.  Unrecognized query mechanisms MUST be ignored.
     */
    const IntArray *keyretr = DkimSignature_getQueryMethod(signature);
    size_t num = IntArray_getCount(keyretr);
    for (size_t n = 0; n < num; ++n) {
        DkimQueryMethod keyretr_method = (DkimQueryMethod) IntArray_get(keyretr, n);
        switch (keyretr_method) {
        case DKIM_QUERY_METHOD_DNS_TXT:;
            DkimStatus retr_dstat = DkimPublicKey_retrieve(policy, signature, resolver, publickey);
            if (DSTAT_OK == retr_dstat) {
                return DSTAT_OK;
            } else if (DSTAT_ISCRITERR(retr_dstat) || DSTAT_ISTMPERR(retr_dstat)) {
                // return immediately on system or DNS errors
                return retr_dstat;
            }   // end if
            break;

        case DKIM_QUERY_METHOD_NULL:
        default:
            DkimLogImplError("unexpected public key retrieving method: keyretr_method=0x%x",
                             keyretr_method);
            return DSTAT_SYSERR_IMPLERROR;
        }   // end switch
    }   // end for

    // no valid public key record is found
    DkimLogPermFail("no valid public key record is found: domain=%s, selector=%s",
                    DkimSignature_getSdid(signature), DkimSignature_getSelector(signature));
    return DSTAT_PERMFAIL_NO_KEY_FOR_SIGNATURE;
}   // end function: DkimPublicKey_lookupImpl

/**
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 * @error DSTAT_SYSERR_IMPLERROR obvious implementation error
 * @error DSTAT_PERMFAIL_NO_KEY_FOR_SIGNATURE Public key record does not exist
 * @error DSTAT_PERMFAIL_KEY_TOO_WEAK the key used to sign is weaker than verifier policy
 * @error DSTAT_TMPERR_DNS_ERROR_RESPONSE DNS lookup error (received error response)
 * @error DSTAT_SYSERR_DNS_LOOKUP_FAILURE DNS lookup error (failed to lookup itself)
 */
DkimStatus
DkimPublicKey_lookup(const DkimVerificationPolicy *policy, const DkimSignature *signature,
                     DnsResolver *resolver, DkimPublicKey **publickey)
{
    assert(NULL != signature);
    assert(NULL != resolver);
    assert(NULL != publickey);

    DkimStatus lookup_dstat = DkimPublicKey_lookupImpl(policy, signature, resolver, publickey);
    if (DSTAT_OK == lookup_dstat) {
        // check the key length
        switch (EVP_PKEY_base_id((*publickey)->pkey)) {
        case EVP_PKEY_RSA:
            if ((int) policy->min_rsa_key_length > EVP_PKEY_bits((*publickey)->pkey)) {
                DkimLogPermFail
                    ("the key length is not enough for verifier's policy: key=%dbits, policy=%dbits",
                     (int) EVP_PKEY_bits((*publickey)->pkey), (int) policy->min_rsa_key_length);
                DkimPublicKey_free(*publickey);
                publickey = NULL;
                return DSTAT_PERMFAIL_KEY_TOO_WEAK;
            }   // end if
            break;
        default:
            // no other public-key cryptography algorithm is defined in DKIM specifications for now.
            break;
        }   // end switch
    }   // end if
    return lookup_dstat;
}   // end function: DkimPublicKey_lookup

////////////////////////////////////////////////////////////////////////
// accessor

EVP_PKEY *
DkimPublicKey_getPublicKey(const DkimPublicKey *self)
{
    return self->pkey;
}   // end function: DkimPublicKey_getPublicKey

bool
DkimPublicKey_isTesting(const DkimPublicKey *self)
{
    return bool_cast((self->selector_flag) & DKIM_SELECTOR_FLAG_TESTING);
}   // end function: DkimPublicKey_isTesting

bool
DkimPublicKey_isSubdomainProhibited(const DkimPublicKey *self)
{
    return bool_cast((self->selector_flag) & DKIM_SELECTOR_FLAG_PROHIBIT_SUBDOMAIN);
}   // end function: DkimPublicKey_isSubdomainProhibited

bool
DkimPublicKey_isEMailServiceUsable(const DkimPublicKey *self)
{
    return bool_cast((self->service_type) & DKIM_SERVICE_TYPE_EMAIL);
}   // end function: DkimPublicKey_isEMailServiceUsable

DkimKeyType
DkimPublicKey_getKeyType(const DkimPublicKey *self)
{
    return self->keytype;
}   // end function: DkimPublicKey_getKeyType

const char *
DkimPublicKey_getGranularity(const DkimPublicKey *self)
{
    return self->granularity;
}   // end function: DkimPublicKey_getGranularity
