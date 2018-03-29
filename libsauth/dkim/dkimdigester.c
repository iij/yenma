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

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <assert.h>
#include <limits.h>

#include <openssl/err.h>
#include <openssl/evp.h>

#include "ptrop.h"
#include "loghandler.h"
#include "dkimlogger.h"
#include "xbuffer.h"
#include "strpairlist.h"
#include "openssl_compat.h"
#include "dkimsignature.h"
#include "dkimcanonicalizer.h"
#include "dkimdigester.h"

struct DkimDigester {
    const EVP_MD *digest_alg;
    int pubkey_alg;
    EVP_MD_CTX *header_digest;
    EVP_MD_CTX *body_digest;
    DkimCanonicalizer *canon;
    bool keep_leading_header_space;
    /// body length limit. sig-l-tag itself. -1 for unlimited.
    long long body_length_limit;
    /// the number of octets included in the hash value at the time.
    long long current_body_length;

    FILE *fp_c14n_header;
    FILE *fp_c14n_body;
};

static void
DkimDigester_logOpenSSLErrors(void)
{
    unsigned long errinfo;
    const char *errfilename, *errstr;
    int errline, errflags;

    while (0 != (errinfo = ERR_get_error_line_data(&errfilename, &errline, &errstr, &errflags))) {
        DkimLogSysError("[OpenSSL] module=%s, function=%s, reason=%s",
                        ERR_lib_error_string(errinfo), ERR_func_error_string(errinfo),
                        ERR_reason_error_string(errinfo));
        DkimLogSysError("[OpenSSL] file=%s, line=%d, error=%s", errfilename, errline,
                        (errflags & ERR_TXT_STRING) ? errstr : "(none)");
    }   // end while
}   // end function: DkimDigester_logOpenSSLErrors

/*
 * get ready to dump the canonicalized message
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_WARN_CANONDUMP_OPEN_FAILURE failed to open files to debug
 */
DkimStatus
DkimDigester_enableC14nDump(DkimDigester *self, const char *header_dump_filename,
                            const char *body_dump_filename)
{
    assert(NULL != self);
    assert(NULL == self->fp_c14n_header);
    assert(NULL == self->fp_c14n_body);

    self->fp_c14n_header = fopen(header_dump_filename, "wb");
    if (NULL == self->fp_c14n_header) {
        LogNotice("failed to open header-c14n-dump file: %s", header_dump_filename);
        return DSTAT_WARN_CANONDUMP_OPEN_FAILURE;
    }   // end if
    self->fp_c14n_body = fopen(body_dump_filename, "wb");
    if (NULL == self->fp_c14n_body) {
        fclose(self->fp_c14n_header);
        LogNotice("failed to open body-c14n-dump file: %s", body_dump_filename);
        return DSTAT_WARN_CANONDUMP_OPEN_FAILURE;
    }   // end if
    return DSTAT_OK;
}   // end function: DkimDigester_enableC14nDump

/**
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 */
static DkimStatus
DkimDigester_dumpCanonicalizedHeader(DkimDigester *self, const void *data, size_t len)
{
    if (NULL != self->fp_c14n_header) {
        if (0 == fwrite(data, 1, len, self->fp_c14n_header)) {
            LogNotice("canonicalized data dump (for header) failed");
            return DSTAT_WARN_CANONDUMP_UPDATE_FAILURE;
        }   // end if
    }   // end if
    return DSTAT_OK;
}   // end function: DkimDigester_dumpCanonicalizedHeader

/**
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 */
static DkimStatus
DkimDigester_dumpCanonicalizedBody(DkimDigester *self, const void *data, size_t len)
{
    if (NULL != self->fp_c14n_body) {
        if (0 == fwrite(data, 1, len, self->fp_c14n_body)) {
            LogNotice("canonicalized data dump (for body) failed");
            return DSTAT_WARN_CANONDUMP_UPDATE_FAILURE;
        }   // end if
    }   // end if
    return DSTAT_OK;
}   // end function: DkimDigester_dumpCanonicalizedBody

/**
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 */
static DkimStatus
DkimDigester_closeC14nDump(DkimDigester *self)
{
    if (NULL != self->fp_c14n_header) {
        (void) fclose(self->fp_c14n_header);
        self->fp_c14n_header = NULL;
    }   // end if
    if (NULL != self->fp_c14n_body) {
        (void) fclose(self->fp_c14n_body);
        self->fp_c14n_body = NULL;
    }   // end if
    return DSTAT_OK;
}   // end function: DkimDigester_closeC14nDump

/**
 * create DkimDigester object with the DkimSignature object
 * @param dstat a pointer to a variable to receive the status code if an error occurred.
 *              possible value of status codes are listed with error tags below.
 * @return initialized DkimDigester object
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 * @error DSTAT_PERMFAIL_UNSUPPORTED_HASH_ALGORITHM unsupported digest algorithm
 * @error DSTAT_PERMFAIL_UNSUPPORTED_KEY_ALGORITHM unsupported public key algorithm
 */
DkimStatus
DkimDigester_newWithSignature(const DkimSignature *signature, bool keep_leading_header_space,
                              DkimDigester **digester)
{
    return DkimDigester_new(DkimSignature_getHashAlgorithm(signature),
                            DkimSignature_getKeyType(signature),
                            DkimSignature_getHeaderC14nAlgorithm(signature),
                            DkimSignature_getBodyC14nAlgorithm(signature),
                            DkimSignature_getBodyLengthLimit(signature),
                            keep_leading_header_space, digester);
}   // end function: DkimDigester_newWithSignature

/**
 * create DkimDigester object
 * @param dstat a pointer to a variable to receive the status code if an error occurred.
 *              possible value of status codes are listed with error tags below.
 * @return initialized DkimDigester object, or NULL if memory allocation failed.
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 * @error DSTAT_PERMFAIL_UNSUPPORTED_HASH_ALGORITHM unsupported digest algorithm
 * @error DSTAT_PERMFAIL_UNSUPPORTED_KEY_ALGORITHM unsupported public key algorithm
 */
DkimStatus
DkimDigester_new(DkimHashAlgorithm digest_alg,
                 DkimKeyType pubkey_alg, DkimC14nAlgorithm header_canon_alg,
                 DkimC14nAlgorithm body_canon_alg, long long body_length_limit,
                 bool keep_leading_header_space, DkimDigester **digester)
{
    assert(NULL != digester);

    DkimDigester *self = (DkimDigester *) malloc(sizeof(DkimDigester));
    if (NULL == self) {
        LogNoResource();
        return DSTAT_SYSERR_NORESOURCE;
    }   // end if
    memset(self, 0, sizeof(DkimDigester));

    switch (digest_alg) {
    case DKIM_HASH_ALGORITHM_SHA1:
        self->digest_alg = EVP_sha1();
        break;
    case DKIM_HASH_ALGORITHM_SHA256:
        self->digest_alg = EVP_sha256();
        break;
    default:
        DkimLogPermFail("unsupported digest algorithm specified: digestalg=0x%x", digest_alg);
        DkimDigester_free(self);
        return DSTAT_PERMFAIL_UNSUPPORTED_HASH_ALGORITHM;
    }   // end switch

    switch (pubkey_alg) {
    case DKIM_KEY_TYPE_RSA:
        self->pubkey_alg = EVP_PKEY_RSA;
        break;
#if defined(EVP_PKEY_ED25519)
    case DKIM_KEY_TYPE_ED25519:
        self->pubkey_alg = EVP_PKEY_ED25519;
        break;
#endif
    default:
        DkimLogPermFail("unsupported public key algorithm specified: pubkeyalg=0x%x", pubkey_alg);
        DkimDigester_free(self);
        return DSTAT_PERMFAIL_UNSUPPORTED_KEY_ALGORITHM;
    }   // end switch

    DkimStatus canon_stat = DkimCanonicalizer_new(header_canon_alg, body_canon_alg, &(self->canon));
    if (DSTAT_OK != canon_stat) {
        DkimDigester_free(self);
        return canon_stat;
    }   // end if
    if (NULL == (self->header_digest = EVP_MD_CTX_new())) {
        LogNoResource();
        DkimDigester_free(self);
        return DSTAT_SYSERR_NORESOURCE;
    }   // end if
    if (0 == EVP_DigestInit(self->header_digest, self->digest_alg)) {
        DkimLogSysError("Digest Initialization (of header) failed");
        DkimDigester_logOpenSSLErrors();
        DkimDigester_free(self);
        return DSTAT_SYSERR_NORESOURCE;
    }   // end if
    if (NULL == (self->body_digest = EVP_MD_CTX_new())) {
        LogNoResource();
        DkimDigester_free(self);
        return DSTAT_SYSERR_NORESOURCE;
    }   // end if
    if (0 == EVP_DigestInit(self->body_digest, self->digest_alg)) {
        DkimLogSysError("Digest Initialization (of body) failed");
        DkimDigester_logOpenSSLErrors();
        DkimDigester_free(self);
        return DSTAT_SYSERR_NORESOURCE;
    }   // end if

    self->body_length_limit = body_length_limit;
    self->keep_leading_header_space = keep_leading_header_space;

    *digester = self;
    return DSTAT_OK;
}   // end function: DkimDigester_new

/**
 * release DkimDigester object
 * @param self DkimDigester object to be released
 */
void
DkimDigester_free(DkimDigester *self)
{
    if (NULL == self) {
        return;
    }   // end if

    (void) DkimDigester_closeC14nDump(self);
    DkimCanonicalizer_free(self->canon);

    if (NULL != self->header_digest) {
        EVP_MD_CTX_free(self->header_digest);
    }
    if (NULL != self->body_digest) {
        EVP_MD_CTX_free(self->body_digest);
    }

    // No need to clean up "self->digest_alg"

    free(self);
}   // end function: DkimDigester_free

/**
  * update digest value of message body
 * @param self DkimDigester object
 * @param buf (a chunk of) canonicalized message body
 * @param len length of buf
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 * @error DSTAT_SYSERR_IMPLERROR obvious implementation error
 * @error DSTAT_SYSERR_DIGEST_UPDATE_FAILURE error on digest update (returned by OpenSSL EVP_DigestUpdate())
 */
static DkimStatus
DkimDigester_updateBodyChunk(DkimDigester *self, const unsigned char *buf, size_t len)
{
    /*
     * [RFC6376] 5.3.1.
     * The body length count allows the Signer of a message to permit data
     * to be appended to the end of the body of a signed message.  The body
     * length count MUST be calculated following the canonicalization
     * algorithm; for example, any whitespace ignored by a canonicalization
     * algorithm is not included as part of the body length count.
     */
    long long srclen = len;
    if (0 <= self->body_length_limit) {
        if (self->body_length_limit < self->current_body_length) {
            // Message body octets more than the body length limit are already included in the digest.
            DkimLogImplError("body length limit over detected");
            return DSTAT_SYSERR_IMPLERROR;
        }   // end if
        if (self->body_length_limit < self->current_body_length + srclen) {
            // discard the part of message body exceeds body length limit
            srclen = self->body_length_limit - self->current_body_length;
        }   // end if
    }   // end if

    if (0 < srclen) {
        if (0 == EVP_DigestUpdate(self->body_digest, buf, srclen)) {
            DkimLogSysError("Digest update (of body) failed");
            DkimDigester_logOpenSSLErrors();
            return DSTAT_SYSERR_DIGEST_UPDATE_FAILURE;
        }   // end if

        // discard errors occurred in functions for debugging
        (void) DkimDigester_dumpCanonicalizedBody(self, buf, srclen);

        self->current_body_length += srclen;
    }   // end if
    return DSTAT_OK;
}   // end function: DkimDigester_updateBodyChunk

/**
 * update digest value of message body
 * @param self DkimDigester object
 * @param buf (a chunk of) message body
 * @param len length of buf
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 */
DkimStatus
DkimDigester_updateBody(DkimDigester *self, const unsigned char *buf, size_t len)
{
    assert(NULL != self);
    assert(NULL != buf);

    if (0 <= self->body_length_limit && self->body_length_limit <= self->current_body_length) {
        // return if the body length limit is already exceeded.
        return DSTAT_OK;
    }   // end if

    const unsigned char *canonbuf;
    size_t canonsize;
    DkimStatus canon_stat = DkimCanonicalizer_body(self->canon, buf, len, &canonbuf, &canonsize);
    if (DSTAT_OK != canon_stat) {
        return canon_stat;
    }   // end if
    // update digest after canonicalization
    return DkimDigester_updateBodyChunk(self, canonbuf, canonsize);
}   // end function: DkimDigester_updateBody

/**
 * update digest value of message header
 * @param self DkimDigester object
 * @param headerf header field name which does *NOT* include the colon separator (':')
 * @param headerv header field value of which does *NOT* include the CRLF at the end
 * @param crlf true to append CRLF to the end of header field after canonicalization. false otherwise.
 * @param keep_leading_header_space
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 * @error DSTAT_SYSERR_IMPLERROR obvious implementation error
 * @error DSTAT_SYSERR_DIGEST_UPDATE_FAILURE error on digest update (returned by OpenSSL EVP_DigestUpdate())
 */
static DkimStatus
DkimDigester_updateHeader(DkimDigester *self, const char *headerf, const char *headerv, bool crlf,
                          bool keep_leading_header_space)
{
    const unsigned char *canonbuf;
    size_t canonsize;
    DkimStatus canon_stat =
        DkimCanonicalizer_header(self->canon, headerf, headerv, crlf, keep_leading_header_space,
                                 &canonbuf, &canonsize);
    if (DSTAT_OK != canon_stat) {
        return canon_stat;
    }   // end if

    // discard errors occurred in functions for debugging
    (void) DkimDigester_dumpCanonicalizedHeader(self, canonbuf, canonsize);

    if (0 == EVP_DigestUpdate(self->header_digest, canonbuf, canonsize)) {
        DkimLogSysError("Digest update (of header) failed");
        DkimDigester_logOpenSSLErrors();
        return DSTAT_SYSERR_DIGEST_UPDATE_FAILURE;
    }   // end if

    return DSTAT_OK;
}   // end function: DkimDigester_updateHeader

/**
 * update digest value of message headers
 * @param self DkimDigester object
 * @param headers InetMailHeaders object that stores all headers.
 * @param signed_headers The names of the header fields included in the digest of the signature.
 *                       The parsed sig-h-tag itself.
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 * @error DSTAT_SYSERR_IMPLERROR obvious implementation error
 * @error DSTAT_SYSERR_DIGEST_UPDATE_FAILURE error on digest update (returned by OpenSSL EVP_DigestUpdate())
 */
static DkimStatus
DkimDigester_updateSignedHeaders(DkimDigester *self, const InetMailHeaders *headers,
                                 const StrArray *signed_headers)
{
    size_t n;
    DkimStatus final_stat;

    StrPairList *kvl = StrPairList_new();
    if (NULL == kvl) {
        LogNoResource();
        return DSTAT_SYSERR_NORESOURCE;
    }   // end if

    // make a shallow copy of "headers"
    StrPairListItem *cur = StrPairList_tail(kvl);
    size_t headernum = InetMailHeaders_getCount(headers);
    for (n = 0; n < headernum; ++n) {
        const char *key, *val;
        InetMailHeaders_get(headers, n, &key, &val);
        cur = StrPairList_insertShallowly(kvl, cur, key, val);
        if (NULL == cur) {
            LogNoResource();
            final_stat = DSTAT_SYSERR_NORESOURCE;
            goto finally;
        }   // end if
    }   // end if

    // choose header fields according to "signed_headers"
    size_t signed_header_num = StrArray_getCount(signed_headers);
    for (n = 0; n < signed_header_num; ++n) {
        const char *headerf = StrArray_get(signed_headers, n);
        /*
         * [RFC6376] 5.4.2.
         * Signers choosing to sign an existing header field that occurs more
         * than once in the message (such as Received) MUST sign the physically
         * last instance of that header field in the header block.  Signers
         * wishing to sign multiple instances of such a header field MUST
         * include the header field name multiple times in the "h=" tag of the
         * DKIM-Signature header field and MUST sign such header fields in order
         * from the bottom of the header field block to the top.
         */
        cur = StrPairList_rfindIgnoreCaseByKey(kvl, headerf, NULL);
        if (NULL != cur) {
            DkimStatus
              update_stat = DkimDigester_updateHeader(self, StrPairListItem_key(cur),
                                                      StrPairListItem_value(cur), true,
                                                      self->keep_leading_header_space);
            if (DSTAT_OK != update_stat) {
                final_stat = update_stat;
                goto finally;
            }   // end if
            StrPairList_deleteShallowly(kvl, cur);
        } else {
            /*
             * treat as the null string if the header field specified by the sig-h-tag does not exist.
             * So do nothing here.
             *
             * [RFC6376] 5.4.
             * Signers MAY claim to have signed header fields that do not exist
             * (that is, Signers MAY include the header field name in the "h=" tag
             * even if that header field does not exist in the message).  When
             * computing the signature, the nonexisting header field MUST be treated
             * as the null string (including the header field name, header field
             * value, all punctuation, and the trailing CRLF).
             */
        }   // end if
    }   // end if
    final_stat = DSTAT_OK;

  finally:
    StrPairList_freeShallowly(kvl);
    return final_stat;
}   // end function: DkimDigester_digestHeaders

/**
 * update the digest with the DKIM-Signature header
 * @param self DkimDigester object
 * @param signature DkimSignature object
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 * @error DSTAT_SYSERR_IMPLERROR obvious implementation error
 * @error DSTAT_SYSERR_DIGEST_UPDATE_FAILURE error on digest update (returned by OpenSSL EVP_DigestUpdate())
 */
static DkimStatus
DkimDigester_updateSignatureHeader(DkimDigester *self, const DkimSignature *signature)
{
    const unsigned char *canonbuf;
    size_t canonsize;
    const char *rawheaderf = DkimSignature_getRawHeaderName(signature);
    const char *rawheaderv = DkimSignature_getRawHeaderValue(signature);
    const char *b_tag_value_head;
    const char *b_tag_value_tail;
    DkimSignature_getReferenceToBodyHashOfRawHeaderValue(signature, &b_tag_value_head,
                                                         &b_tag_value_tail);
    DkimStatus
      canon_stat = DkimCanonicalizer_signheader(self->canon, rawheaderf, rawheaderv,
                                                self->keep_leading_header_space,
                                                b_tag_value_head, b_tag_value_tail,
                                                &canonbuf, &canonsize);
    if (DSTAT_OK != canon_stat) {
        return canon_stat;
    }   // end if

    // discard errors occurred in functions for debugging
    (void) DkimDigester_dumpCanonicalizedHeader(self, canonbuf, canonsize);

    // update digest
    if (0 == EVP_DigestUpdate(self->header_digest, canonbuf, canonsize)) {
        DkimLogSysError("Digest update (of signature header) failed");
        DkimDigester_logOpenSSLErrors();
        return DSTAT_SYSERR_DIGEST_UPDATE_FAILURE;
    }   // end if

    return DSTAT_OK;
}   // end function: DkimDigester_updateSignatureHeader

/**
 * compare the digests of the message headers and body to the digest value included in the DKIM-Signature headers
 * @param headers InetMailHeaders object that stores all headers.
 * @param signature DkimSignature object to verify
 * @param pkey public key
 * @return DSTAT_INFO_DIGEST_MATCH if the digest value of message header fields and body matches,
 *         otherwise status code that indicates error.
 * @error DSTAT_PERMFAIL_SIGNATURE_DID_NOT_VERIFY the digest value of the message header fields does not match
 * @error DSTAT_PERMFAIL_BODY_HASH_DID_NOT_VERIFY the digest value of the message body does not match
 * @error other errors
 */
DkimStatus
DkimDigester_verifyMessage(DkimDigester *self, const InetMailHeaders *headers,
                           const DkimSignature *signature, EVP_PKEY *publickey)
{
    assert(NULL != self);
    assert(NULL != headers);
    assert(NULL != signature);
    assert(NULL != publickey);

    const unsigned char *canonbuf;
    const unsigned char *signbuf;
    size_t canonsize, signlen;
    unsigned char md[EVP_MD_size(self->digest_alg)];    // EVP_MAX_MD_SIZE instead of EVP_MD_size() is safer(?)
    unsigned int mdlen;

    // check if the type of the public key is suitable for the algorithm
    // specified by sig-a-tag of the DKIM-Signature header.
    if (EVP_PKEY_base_id(publickey) != self->pubkey_alg) {
        DkimLogPermFail("Public key algorithm mismatch: signature=0x%x, pubkey=0x%x",
                        EVP_PKEY_base_id(publickey), self->pubkey_alg);
        return DSTAT_PERMFAIL_PUBLICKEY_TYPE_MISMATCH;
    }   // end if

    // Calculation and verification of the message body hash.
    // Flush the canonicalization buffer and finalize canonicalization.
    DkimStatus ret = DkimCanonicalizer_finalizeBody(self->canon, &canonbuf, &canonsize);
    if (DSTAT_OK != ret) {
        return ret;
    }   // end if
    // Add the final chunk of the message body into the digest.
    ret = DkimDigester_updateBodyChunk(self, canonbuf, canonsize);
    if (DSTAT_OK != ret) {
        return ret;
    }   // end if
    if (0 == EVP_DigestFinal(self->body_digest, md, &mdlen)) {
        DkimLogSysError("Digest finish (of body) failed");
        DkimDigester_logOpenSSLErrors();
        return DSTAT_SYSERR_DIGEST_UPDATE_FAILURE;
    }   // end if

    // Comparing the digest of the message body prior to the verification of the signature
    const XBuffer *bodyhash = DkimSignature_getBodyHash(signature);
    if (!XBuffer_compareToBytes(bodyhash, md, mdlen)) {
        DkimLogPermFail("Digest of message body mismatch");
        return DSTAT_PERMFAIL_BODY_HASH_DID_NOT_VERIFY;
    }   // end if

    // Add the headers specified by sig-h-tag into the digest.
    ret =
        DkimDigester_updateSignedHeaders(self, headers,
                                         DkimSignature_getSignedHeaderFields(signature));
    if (DSTAT_OK != ret) {
        return ret;
    }   // end if
    // Add DKIM-Signature header into the digest.
    ret = DkimDigester_updateSignatureHeader(self, signature);
    if (DSTAT_OK != ret) {
        return ret;
    }   // end if

    // discard errors occurred in functions for debugging
    (void) DkimDigester_closeC14nDump(self);

    const XBuffer *headerhash = DkimSignature_getSignatureValue(signature);
    signbuf = (const unsigned char *) XBuffer_getBytes(headerhash);
    signlen = XBuffer_getSize(headerhash);
    int vret = EVP_VerifyFinal(self->header_digest, signbuf, signlen, publickey);
    // EVP_VerifyFinal() returns 1 for a correct signature, 0 for failure and -1 if some other error occurred.
    switch (vret) {
    case 1:    // the signature is correct
        return DSTAT_INFO_DIGEST_MATCH;
    case 0:    // the signature is broken
        DkimLogPermFail("Digest of message header mismatch");
        return DSTAT_PERMFAIL_SIGNATURE_DID_NOT_VERIFY;
    case -1:   // some other error occurred
        DkimLogSysError("Digest verification error");
        DkimDigester_logOpenSSLErrors();
        return DSTAT_SYSERR_DIGEST_VERIFICATION_FAILURE;
    default:
        DkimLogImplError("EVP_VerifyFinal returns unexpected value: ret=0x%x", vret);
        DkimDigester_logOpenSSLErrors();
        return DSTAT_SYSERR_IMPLERROR;
    }   // end switch
}   // end function: DkimDigester_verifyMessage

/**
 * generate the digital signature based on the digests of the message headers and body
 * @param headers InetMailHeaders object that stores all headers.
 * @param signature DkimSignature object that stores the digest value calculated in this function.
 *                  "signature_value", "bodyhash", "rawname" and "rawvalue" field of this object are updated in this function.
 *                  "signed_header_fields" field of this object is referred to determine which header fields to be signed.
 * @param pkey private key
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 * @error DSTAT_SYSERR_IMPLERROR obvious implementation error
 * @error DSTAT_SYSERR_DIGEST_UPDATE_FAILURE error on digest update (returned by OpenSSL EVP_DigestUpdate())
 */
DkimStatus
DkimDigester_signMessage(DkimDigester *self, const InetMailHeaders *headers,
                         DkimSignature *signature, EVP_PKEY *privatekey)
{
    assert(NULL != self);
    assert(NULL != headers);
    assert(NULL != signature);
    assert(NULL != privatekey);

    // XXX signature と self の署名/ダイジェストアルゴリズムが一致しているか確認した方がいい
    if (EVP_PKEY_base_id(privatekey) != self->pubkey_alg) {
        DkimLogPermFail("Public key algorithm mismatch: signature=0x%x, privatekey=0x%x",
                        EVP_PKEY_base_id(privatekey), self->pubkey_alg);
        return DSTAT_PERMFAIL_PUBLICKEY_TYPE_MISMATCH;
    }   // end if

    // calculation of the message body hash
    const unsigned char *canonbuf;
    size_t canonsize;
    DkimStatus ret = DkimCanonicalizer_finalizeBody(self->canon, &canonbuf, &canonsize);
    if (DSTAT_OK != ret) {
        return ret;
    }   // end if
    ret = DkimDigester_updateBodyChunk(self, canonbuf, canonsize);
    if (DSTAT_OK != ret) {
        return ret;
    }   // end if

    unsigned char bodyhashbuf[EVP_MD_size(self->digest_alg)];   // EVP_MAX_MD_SIZE instead of EVP_MD_size() is safer(?)
    unsigned int bodyhashlen;
    bodyhashlen = EVP_MD_size(self->digest_alg);
    if (0 == EVP_DigestFinal(self->body_digest, bodyhashbuf, &bodyhashlen)) {
        DkimLogSysError("DigestFinal (of body) failed");
        DkimDigester_logOpenSSLErrors();
        return DSTAT_SYSERR_DIGEST_UPDATE_FAILURE;
    }   // end if
    ret = DkimSignature_setBodyHash(signature, bodyhashbuf, bodyhashlen);
    if (DSTAT_OK != ret) {
        return ret;
    }   // end if

    // calculation of the message headers hash
    ret =
        DkimDigester_updateSignedHeaders(self, headers,
                                         DkimSignature_getSignedHeaderFields(signature));
    if (DSTAT_OK != ret) {
        return ret;
    }   // end if

    // generate DKIM-Signature header without sig-b-tag
    const char *rawheaderf, *rawheaderv;
    ret = DkimSignature_buildRawHeader(signature, true, true, true, &rawheaderf, &rawheaderv);
    if (DSTAT_OK != ret) {
        return ret;
    }   // end if

    // DKIM-Signature header without sig-b-tag should be included in the header hash
    // as same as the other headers.
    // DKIM-Signature header doesn't include trailing CRLF.
    // SP (space, 0x20) is supplied after the colon separating
    // the DKIM-Signature header field name from the header field value.
    ret = DkimDigester_updateHeader(self, rawheaderf, rawheaderv, false, true);
    if (DSTAT_OK != ret) {
        return ret;
    }   // end if

    // discard errors occurred in functions for debugging
    (void) DkimDigester_closeC14nDump(self);

    unsigned char signbuf[EVP_PKEY_size(privatekey)];
    unsigned int signlen;
    if (0 == EVP_SignFinal(self->header_digest, signbuf, &signlen, privatekey)) {
        DkimLogSysError("SignFinal (of body) failed");
        DkimDigester_logOpenSSLErrors();
        return DSTAT_SYSERR_DIGEST_UPDATE_FAILURE;
    }   // end if
    ret = DkimSignature_setSignatureValue(signature, signbuf, signlen);
    if (DSTAT_OK != ret) {
        return ret;
    }   // end if

    return DSTAT_OK;
}   // end function: DkimDigester_signMessage
