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
#include <sys/param.h>
#include <sys/types.h>
#include <stdbool.h>

#include <openssl/evp.h>

#include "stdaux.h"
#include "intarray.h"
#include "strarray.h"
#include "pstring.h"
#include "ptrop.h"
#include "inetdomain.h"
#include "inetmailbox.h"
#include "inetmailheaders.h"
#include "loghandler.h"
#include "dkimlogger.h"
#include "dkim.h"
#include "dkimenum.h"
#include "dkimspec.h"
#include "dkimpublickey.h"
#include "dkimadsp.h"
#include "dkimatps.h"
#include "dkimsignature.h"
#include "dkimdigester.h"
#include "dkimverificationpolicy.h"

typedef struct DkimVerificationFrame {
    /// status of the verification process for each DKIM-Signature header
    DkimStatus status;
    /// DkimSignature object build by parsing the corresponding DKIM-Signature header
    DkimSignature *signature;
    /// DkimPublicKey object corresponding to the DKIM-Signature header
    DkimPublicKey *publickey;
    /// DkimDigester object to computes a message hash
    DkimDigester *digester;
    /// DKIM verification results
    DkimFrameResult result;
} DkimVerificationFrame;

typedef struct DkimPolicyFrame {
    InetMailbox *author;
    /// ADSP record
    DkimAdsp *adsp;
    /// DKIM ADSP score (as cache)
    DkimAdspScore adsp_score;
    /// DKIM ATPS score (as cache)
    DkimAtpsScore atps_score;
} DkimPolicyFrame;

typedef PtrArray DkimVerificationFrameArray;
typedef PtrArray DkimPolicyFrameArray;

struct DkimVerifier {
    /// Verification policy
    const DkimVerificationPolicy *vpolicy;
    /// status of whole of the verification process
    DkimStatus status;

    // DNS resolver
    DnsResolver *resolver;

    bool keep_leading_header_space;

    /// the number of DKIM-Signature headers included in the InetMailHeaders object referenced by "headers" field
    /// this number may be more than the number of DkimVerificationFrame
    size_t sigheader_num;

    /// reference to InetMailHeaders object
    const InetMailHeaders *headers;
    /// Array of DkimVerificationFrame
    DkimVerificationFrameArray *vframe;
    bool have_temporary_error;
    bool have_system_error;
    /// Array of DkimPolicyFrame
    DkimPolicyFrameArray *pframe;
};

#define DkimVerificationFrameArray_new(__a)  PtrArray_new(__a, (void (*)(void *)) DkimVerificationFrame_free)
#define DkimVerificationFrameArray_free(__a)  PtrArray_free(__a)
#define DkimVerificationFrameArray_append(__a, __b)  PtrArray_append(__a, __b)
#define DkimVerificationFrameArray_getCount(__a)  PtrArray_getCount(__a)
#define DkimVerificationFrameArray_get(__a, __b)  ((DkimVerificationFrame *) PtrArray_get(__a, __b))

#define DkimPolicyFrameArray_new(__a)  PtrArray_new(__a, (void (*)(void *)) DkimPolicyFrame_free)
#define DkimPolicyFrameArray_free(__a)  PtrArray_free(__a)
#define DkimPolicyFrameArray_set(__a, __b, __c)  PtrArray_set(__a, __b, __c)
#define DkimPolicyFrameArray_getCount(__a)  PtrArray_getCount(__a)
#define DkimPolicyFrameArray_get(__a, __b)  ((DkimPolicyFrame *) PtrArray_get(__a, __b))

static const DkimFrameResult toomany_sig_result = {
    DKIM_BASE_SCORE_POLICY, DSTAT_POLICY_TOOMANY_SIGNATURES, false, NULL, NULL, 0
};

/**
 * create DkimVerificationFrame object
 * @return initialized DkimVerificationFrame object, or NULL if memory allocation failed.
 */
static DkimVerificationFrame *
DkimVerificationFrame_new(void)
{
    DkimVerificationFrame *self = (DkimVerificationFrame *) malloc(sizeof(DkimVerificationFrame));
    if (NULL == self) {
        return NULL;
    }   // end if
    memset(self, 0, sizeof(DkimVerificationFrame));

    self->status = DSTAT_OK;
    self->result.score = DKIM_BASE_SCORE_NULL;

    return self;
}   // end function: DkimVerificationFrame_new

/**
 * release DkimVerificationFrame object
 * @param self DkimVerificationFrame object to be released
 */
static void
DkimVerificationFrame_free(DkimVerificationFrame *self)
{
    if (NULL == self) {
        return;
    }   // end if

    DkimDigester_free(self->digester);
    DkimSignature_free(self->signature);
    DkimPublicKey_free(self->publickey);
    free(self);
}   // end function: DkimVerificationFrame_free

static DkimPolicyFrame *
DkimPolicyFrame_new(void)
{
    DkimPolicyFrame *self = (DkimPolicyFrame *) malloc(sizeof(DkimPolicyFrame));
    if (NULL == self) {
        return NULL;
    }   // end if
    memset(self, 0, sizeof(DkimPolicyFrame));
    self->adsp_score = DKIM_ADSP_SCORE_NULL;
    self->atps_score = DKIM_ATPS_SCORE_NULL;
    return self;
}   // end function: DkimPolicyFrame_new

static bool
DkimVerificationFrame_isTesting(const DkimVerificationFrame *self)
{
    return bool_cast(NULL != self->publickey && DkimPublicKey_isTesting(self->publickey));
}   // end function: DkimVerificationFrame_isTesting

static bool
DkimVerificationFrame_isSignatureVerified(const DkimVerificationFrame *self)
{
    return bool_cast(DSTAT_INFO_DIGEST_MATCH == self->status
                     && !DkimVerificationFrame_isTesting(self));
}   // end function: DkimVerificationFrame_isSignatureVerified

/**
 * @param self DkimVerificationFrame object
 */
static void
DkimVerificationFrame_buildResult(DkimVerificationFrame *self)
{
    // If the score is cached and the status does not changed, just return
    if (DKIM_BASE_SCORE_NULL != self->result.score && self->result.stauts == self->status) {
        return;
    }   // end if

    self->result.stauts = self->status;
    self->result.testing = DkimVerificationFrame_isTesting(self);
    self->result.sdid = (NULL != self->signature ? DkimSignature_getSdid(self->signature) : NULL);
    self->result.auid = (NULL != self->signature ? DkimSignature_getAuid(self->signature) : NULL);
    EVP_PKEY *pkey = NULL;
    if (NULL != self->publickey && NULL != (pkey = DkimPublicKey_getPublicKey(self->publickey))) {
        self->result.pkey_bits = EVP_PKEY_bits(pkey);
    } else {
        self->result.pkey_bits = -1;
    }   // end if

    if (DSTAT_ISTMPERR(self->status) || DSTAT_ISSYSERR(self->status)) {
        self->result.score = DKIM_BASE_SCORE_TEMPERROR;
        return;
    }   // end if

    switch (self->status) {
    case DSTAT_INFO_DIGEST_MATCH:
        /*
         * [RFC5451] 2.4.1.
         * pass:  The message was signed, the signature or signatures were
         *    acceptable to the verifier, and the signature(s) passed
         *    verification tests.
         */
        self->result.score = DKIM_BASE_SCORE_PASS;
        break;
    case DSTAT_PERMFAIL_SIGNATURE_DID_NOT_VERIFY:
    case DSTAT_PERMFAIL_BODY_HASH_DID_NOT_VERIFY:
        /*
         * [RFC5451] 2.4.1.
         * fail:  The message was signed and the signature or signatures were
         *    acceptable to the verifier, but they failed the verification
         *    test(s).
         */
        self->result.score = DKIM_BASE_SCORE_FAIL;
        break;
    default:
        /*
         * [RFC5451] 2.4.1.
         * neutral:  The message was signed but the signature or signatures
         *    contained syntax errors or were not otherwise able to be
         *    processed.  This result SHOULD also be used for other failures not
         *    covered elsewhere in this list.
         */
        self->result.score = DKIM_BASE_SCORE_NEUTRAL;
        break;
    }   // end switch
    return;
}   // end function: DkimVerificationFrame_buildResult

/**
 * release DkimPolicyFrame object
 * @param self DkimPolicyFrame object to be released
 */
static void
DkimPolicyFrame_free(DkimPolicyFrame *self)
{
    if (NULL == self) {
        return;
    }   // end if
    DkimAdsp_free(self->adsp);
    InetMailbox_free(self->author);
    free(self);
}   // end function: DkimPolicyFrame_free

static DkimPolicyFrame *
DkimPolicyFrameArray_allocate(DkimPolicyFrameArray *self, size_t idx, const InetMailbox *author)
{
    InetMailbox *dupauthor = NULL;
    if (NULL != author) {
        dupauthor = InetMailbox_duplicate(author);
        if (NULL == dupauthor) {
            return NULL;
        }   // end if
    }   // end if

    DkimPolicyFrame *pframe = NULL;
    if (DkimPolicyFrameArray_getCount(self) <= idx
        || NULL == (pframe = DkimPolicyFrameArray_get(self, idx))) {
        pframe = DkimPolicyFrame_new();
        if (NULL == pframe) {
            goto cleanup;
        }   // end if
        if (0 > DkimPolicyFrameArray_set(self, idx, pframe)) {
            DkimPolicyFrame_free(pframe);
            goto cleanup;
        }   // end if
    }   // end if

    if (NULL != pframe->author) {
        InetMailbox_free(pframe->author);
    }   // end if

    pframe->author = dupauthor;
    pframe->adsp_score = DKIM_ADSP_SCORE_NULL;
    pframe->atps_score = DKIM_ATPS_SCORE_NULL;
    return pframe;

  cleanup:
    InetMailbox_free(dupauthor);
    return NULL;
}   // end function: DkimPolicyFrameArray_allocate

/**
 * release DkimVerifier object
 * @param self DkimVerifier object to release
 */
void
DkimVerifier_free(DkimVerifier *self)
{
    if (NULL == self) {
        return;
    }   // end if

    // self->headers must not be released. it is just a reference.
    DkimVerificationFrameArray_free(self->vframe);
    DkimPolicyFrameArray_free(self->pframe);
    free(self);
}   // end function: DkimVerifier_free

/**
 * @param self DkimVerifier object
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 */
static DkimStatus
DkimVerifier_setupFrame(DkimVerifier *self, const char *headerf, const char *headerv)
{
    // create a verification frame
    DkimVerificationFrame *frame = DkimVerificationFrame_new();
    if (NULL == frame) {
        LogNoResource();
        return self->status = DSTAT_SYSERR_NORESOURCE;
    }   // end if

    // register DkimVerificationFrame immediately even if corresponding
    // DKIM-Signature header is invalid as a result.
    if (0 > DkimVerificationFrameArray_append(self->vframe, frame)) {
        DkimVerificationFrame_free(frame);
        LogNoResource();
        return self->status = DSTAT_SYSERR_NORESOURCE;
    }   // end if

    // parse and verify DKIM-Signature header
    frame->status = DkimSignature_build(headerf, headerv, &(frame->signature));
    if (DSTAT_OK != frame->status) {
        return frame->status;
    }   // end if

    // check expiration of the signature if an expired signature is unacceptable.
    if (!self->vpolicy->accept_expired_signature) {
        frame->status = DkimSignature_isExpired(frame->signature);
        if (DSTAT_OK != frame->status) {
            return frame->status;
        }   // end if
    }   // end if

    // check whether the signature has a future timestamp
    if (!self->vpolicy->accept_future_signature) {
        frame->status = DkimSignature_checkFutureTimestamp(frame->signature);
        if (DSTAT_OK != frame->status) {
            return frame->status;
        }   // end if
    }   // end if

    // The DKIM-Signature header has been confirmed as syntactically valid.
    // log the essentials of the signature accepted
    LogInfo
        ("DKIM-Signature[%u]: domain=%s, selector=%s, pubkeyalg=%s, digestalg=%s, hdrcanon=%s, bodycanon=%s",
         (unsigned int) self->sigheader_num,
         InetMailbox_getDomain(DkimSignature_getAuid(frame->signature)),
         DkimSignature_getSelector(frame->signature),
         DkimEnum_lookupKeyTypeByValue(DkimSignature_getKeyType(frame->signature)),
         DkimEnum_lookupHashAlgorithmByValue(DkimSignature_getHashAlgorithm(frame->signature)),
         DkimEnum_lookupC14nAlgorithmByValue(DkimSignature_getHeaderC14nAlgorithm
                                             (frame->signature)),
         DkimEnum_lookupC14nAlgorithmByValue(DkimSignature_getBodyC14nAlgorithm(frame->signature)));

    // retrieve public key
    frame->status =
        DkimPublicKey_lookup(self->vpolicy, frame->signature, self->resolver, &(frame->publickey));
    if (DSTAT_OK != frame->status) {
        return frame->status;
    }   // end if

    // create DkimDigester object
    frame->status =
        DkimDigester_newWithSignature(frame->signature, self->keep_leading_header_space,
                                      &(frame->digester));
    if (DSTAT_OK != frame->status) {
        return frame->status;
    }   // end if

    return DSTAT_OK;
}   // end function: DkimVerifier_setupFrame

/**
 * registers the message headers and checks if the message has any valid signatures.
 * @param vpolicy DkimVerificationPolicy object to be associated with the created DkimVerifier object.
 *                This object can be shared between multiple threads.
 * @param resolver DnsResolver object to look-up public keys record and ADSP records.
 *                This object can *NOT* be shared between multiple threads.
 * @param headers InetMailHeaders object that stores all headers.
 *                Key of InetMailHeaders object is treated as header field name excepting ':'.
 *                Value of InetMailHeaders object is treated as header field value excepting ':',
 *                and it is switchable by keep_leading_header_space
 *                whether or not SP (space) character after ':' is included in header field values.
 *                (sendmail 8.13 or earlier does not include SP in header field value,
 *                sendmail 8.14 or later with SMFIP_HDR_LEADSPC includes it.)
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_INFO_NO_SIGNHEADER No DKIM-Signature headers are found.
 * @error other errors
 */
DkimStatus
DkimVerifier_new(const DkimVerificationPolicy *vpolicy, DnsResolver *resolver,
                 const InetMailHeaders *headers, bool keep_leading_header_space,
                 DkimVerifier **verifier)
{
    assert(NULL != vpolicy);
    assert(NULL != resolver);

    DkimVerifier *self = (DkimVerifier *) malloc(sizeof(DkimVerifier));
    if (NULL == self) {
        LogNoResource();
        return DSTAT_SYSERR_NORESOURCE;
    }   // end if
    memset(self, 0, sizeof(DkimVerifier));

    // minimum initialization
    self->vframe = DkimVerificationFrameArray_new(0);
    if (NULL == self->vframe) {
        LogNoResource();
        DkimVerifier_free(self);
        return DSTAT_SYSERR_NORESOURCE;
    }   // end if

    self->sigheader_num = 0;
    self->vpolicy = vpolicy;
    self->resolver = resolver;
    self->have_temporary_error = false;
    self->have_system_error = false;
    self->keep_leading_header_space = keep_leading_header_space;
    self->headers = headers;

    // setup verification frames as many as DKIM-Signature headers
    size_t headernum = InetMailHeaders_getCount(self->headers);
    for (size_t headeridx = 0; headeridx < headernum; ++headeridx) {
        const char *headerf, *headerv;
        InetMailHeaders_get(self->headers, headeridx, &headerf, &headerv);
        if (NULL == headerf || NULL == headerv) {
            continue;
        }   // end if

        if (0 != strcasecmp(DKIM_SIGNHEADER, headerf)) {
            // headerf is not DKIM-Signature
            continue;
        }   // end if

        // A DKIM-Signature header is found
        ++(self->sigheader_num);

        /*
         * confirm that the number of DKIM-Signature headers included in "headers"
         * is less than or equal to its limit specified by DkimVerificationPolicy.
         *
         * [RFC6376] 6.1.
         * A Verifier MAY limit the number of
         * signatures it tries, in order to avoid denial-of-service attacks
         */
        if (0 < self->vpolicy->sign_header_limit
            && self->vpolicy->sign_header_limit < self->sigheader_num) {
            LogInfo("too many signature headers: count=%zu, limit=%zu",
                    self->sigheader_num, self->vpolicy->sign_header_limit);
            break;
        }   // end if

        DkimStatus setup_stat = DkimVerifier_setupFrame(self, headerf, headerv);
        if (DSTAT_ISCRITERR(setup_stat)) {
            // return on system errors
            DkimVerifier_free(self);
            return setup_stat;
        }   // end if
    }   // end for

    // Are one or more DKIM-Signature headers found?
    size_t framenum = DkimVerificationFrameArray_getCount(self->vframe);
    if (0 == framenum) {
        // message is not DKIM-signed
        *verifier = self;
        return self->status = DSTAT_INFO_NO_SIGNHEADER;
    }   // end if

    // message is DKIM-signed
    *verifier = self;
    return self->status = DSTAT_OK;
}   // end function: DkimVerifier_new

/**
 * @param self DkimVerifier object
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 */
DkimStatus
DkimVerifier_updateBody(DkimVerifier *self, const unsigned char *bodyp, size_t len)
{
    assert(NULL != self);

    if (DSTAT_OK != self->status) {
        // do nothing
        return DSTAT_OK;
    }   // end if

    // update digest for each verification frame
    size_t framenum = DkimVerificationFrameArray_getCount(self->vframe);
    for (size_t frameidx = 0; frameidx < framenum; ++frameidx) {
        DkimVerificationFrame *frame = DkimVerificationFrameArray_get(self->vframe, frameidx);
        // skip verification frames with errors
        if (DSTAT_OK != frame->status) {
            continue;
        }   // end if

        frame->status = DkimDigester_updateBody(frame->digester, bodyp, len);
        if (DSTAT_OK != frame->status) {
            DkimLogPermFail("body digest update failed for signature no.%u",
                            (unsigned int) frameidx);
            // doesn't return to continue the other verification frames
        }   // end if
    }   // end if

    return DSTAT_OK;
}   // end function: DkimVerifier_updateBody

/**
 * @param self DkimVerifier object
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 */
DkimStatus
DkimVerifier_verify(DkimVerifier *self)
{
    assert(NULL != self);

    if (DSTAT_OK != self->status) {
        // do nothing
        return self->status;
    }   // end if

    size_t framenum = DkimVerificationFrameArray_getCount(self->vframe);
    for (size_t frameidx = 0; frameidx < framenum; ++frameidx) {
        DkimVerificationFrame *frame = DkimVerificationFrameArray_get(self->vframe, frameidx);
        // skip verification frames with errors
        if (DSTAT_OK != frame->status) {
            continue;
        }   // end if

        frame->status =
            DkimDigester_verifyMessage(frame->digester, self->headers, frame->signature,
                                       DkimPublicKey_getPublicKey(frame->publickey));
        if (DSTAT_ISTMPERR(frame->status)) {
            self->have_temporary_error = true;
        } else if (DSTAT_ISSYSERR(frame->status)) {
            self->have_system_error = true;
        }   // end if
    }   // end for

    return DSTAT_OK;
}   // end function: DkimVerifier_verify

/**
 * @param self DkimVerifier object
 * @return If verification process successfully completed, DKIM_SCORE_NULL is returned
 *         and call DkimVerifier_getFrameResult() for each result.
 *         Otherwise status code that indicates error.
 */
DkimBaseScore
DkimVerifier_getSessionResult(const DkimVerifier *self)
{
    assert(NULL != self);

    // check the status of whole of the verification process
    switch (self->status) {
    case DSTAT_OK:
        return DKIM_BASE_SCORE_NULL;
    case DSTAT_INFO_NO_SIGNHEADER:
        /*
         * "none" if no DKIM-Signature headers are found
         * [RFC5451] 2.4.1.
         * none:  The message was not signed.
         */
        return DKIM_BASE_SCORE_NONE;
    case DSTAT_SYSERR_NORESOURCE:
    default:
        return DKIM_BASE_SCORE_TEMPERROR;
    }   // end switch
}   // end function: DkimVerifier_getSessionResult

static bool
DkimVerifier_hasAuthorDomainSignature(const DkimVerifier *self, const char *author_domain)
{
    size_t framenum = DkimVerificationFrameArray_getCount(self->vframe);
    for (size_t frameidx = 0; frameidx < framenum; ++frameidx) {
        DkimVerificationFrame *frame = DkimVerificationFrameArray_get(self->vframe, frameidx);
        if (DkimVerificationFrame_isSignatureVerified(frame)) {
            /*
             * [RFC5617] 2.7.
             * An "Author Domain Signature" is a Valid Signature in which the domain
             * name of the DKIM signing entity, i.e., the d= tag in the DKIM-
             * Signature header field, is the same as the domain name in the Author
             * Address.  Following [RFC5321], domain name comparisons are case
             * insensitive.
             */
            const char *sdid = DkimSignature_getSdid(frame->signature);
            if (InetDomain_equals(sdid, author_domain)) {
                // Author Domain Signature (= First Party Signature)
                /*
                 * [draft-kucherawy-sender-auth-header-20] 2.4.2.
                 * pass:  This message had an author signature which validated.  (An
                 *    ADSP check is not strictly required to be performed for this
                 *    result, since a valid author domain signature satisfies all
                 *    possible ADSP policies.)
                 */
                return true;
            }   // end if
        }   // end if
    }   // end for
    return false;
}   // end function: DkimVerifier_hasAuthorDomainSignature

static DkimAtpsScore
DkimVerifier_evalAtps(DkimVerifier *self, const char *author_domain)
{
    bool have_atps_system_error = false;
    bool have_atps_temporary_error = false;
    bool have_atps_permanent_error = false;
    size_t atps_sig_num = 0;    // the number of DKIM signatures bearing "atps" tags
    size_t atps_valid_sig_num = 0;  // the number of valid DKIM signatures bearing "atps" tags

    size_t framenum = DkimVerificationFrameArray_getCount(self->vframe);
    for (size_t frameidx = 0; frameidx < framenum; ++frameidx) {
        DkimVerificationFrame *frame = DkimVerificationFrameArray_get(self->vframe, frameidx);
        if (NULL == frame || NULL == frame->signature) {
            // for broken signatures
            continue;
        }   // end if
        /*
         * [RFC6541] 4.3.
         * When a [DKIM] signature including an "atps" tag is successfully
         * verified, ...
         */
        const char *atps_domain = DkimSignature_getAtpsDomain(frame->signature);
        if (NULL == atps_domain) {
            /*
             * [RFC6541] 4.2.
             * When the ATPS Signer generates a DKIM signature for another ADMD, it
             * MUST put its own domain in the signature's "d" tag, and include an
             * "atps" tag that has as its value the domain name of the ADMD on whose
             * behalf it is signing.
             */
            continue;
        }   // end if
        ++atps_sig_num;

        if (!DkimVerificationFrame_isSignatureVerified(frame)) {
            continue;
        }   // end if
        ++atps_valid_sig_num;

        // all signatures here are valid third-party signature bearing "atps" tags
        DkimHashAlgorithm atps_hashalg = DkimSignature_getAtpsHashAlgorithm(frame->signature);
        if (DKIM_HASH_ALGORITHM_NULL == atps_hashalg) {
            /*
             * [RFC6541] 4.2.
             * The tag name that carries the name of the selected hash algorithm is
             * "atpsh".  This tag MUST also be included, as it is required as part
             * of the algorithm that will be enacted by the Verifier.
             */
            continue;
        }   // end if
        if (!InetDomain_equals(atps_domain, author_domain)) {
            /*
             * [RFC6541] 4.3.
             * ... the Verifier compares the domain name in the value of that
             * tag with the one found in the RFC5322.From field of the message.  The
             * match MUST be done in a case-insensitive manner.
             *
             * If they do not match, the "atps" tag MUST be ignored.
             */
            continue;
        }   // end if
        const char *sdid = DkimSignature_getSdid(frame->signature);
        DkimAtps *atps_record = NULL;
        DkimStatus atps_stat =
            DkimAtps_lookup(atps_domain, sdid, atps_hashalg, self->resolver, &atps_record);
        if (DSTAT_OK == atps_stat) {
            DkimAtps_free(atps_record);
            return DKIM_ATPS_SCORE_PASS;
        } else if (DSTAT_INFO_DNSRR_NOT_EXIST == atps_stat) {
            // try next signature
            ;
        } else if (DSTAT_ISCRITERR(atps_stat)) {
            have_atps_system_error = true;
        } else if (DSTAT_ISTMPERR(atps_stat)) {
            have_atps_temporary_error = true;
        } else if (DSTAT_ISPERMFAIL(atps_stat)) {
            have_atps_permanent_error = true;
        }   // end if
    }   // end for

    if (have_atps_temporary_error || have_atps_system_error) {
        /*
         * [RFC6541] 8.3.
         * Code:     temperror
         * Meaning:  An ADSP record could not be retrieved due to some error
         *           that is likely transient in nature, such as a temporary DNS
         *           error.  A later attempt may produce a final result.
         */
        return DKIM_ATPS_SCORE_TEMPERROR;
    } else if (have_atps_permanent_error) {
        /*
         * [RFC6541] 8.3.
         * Code:     permerror
         * Meaning:  An ADSP record could not be retrieved due to some error
         *           that is likely not transient in nature, such as a permanent
         *           DNS error.  A later attempt is unlikely to produce a final
         *           result.
         */
        return DKIM_ATPS_SCORE_PERMERROR;
    } else if (0 < atps_valid_sig_num) {
        /*
         * [RFC6541] 8.3.
         * Code:  fail
         * Meaning:  All valid DKIM signatures bearing an "atps" tag either did
         *    not reference a domain name found in the RFC5322.From field, or
         *    the ATPS test(s) performed failed to confirm a third-party
         *    authorization.
         */
        return DKIM_ATPS_SCORE_FAIL;
    } else if (0 < atps_sig_num) {
        /*
         * [RFC6541] 8.3.
         * Code:  none
         * Meaning:  No valid DKIM signatures were found on the message bearing
         *    "atps" tags.
         */
        return DKIM_ATPS_SCORE_NONE;
    } else {
        // No DKIM signatures bearing "atps" tags
        return DKIM_ATPS_SCORE_NULL;
    }   // end if
}   // end function: DkimVerifier_evalAtps

static DkimAdspScore
DkimVerifier_evalAdsp(DkimVerifier *self, const char *author_domain, DkimPolicyFrame *pframe)
{
    // retrieving ADSP record if the message doesn't have an author domain signature
    if (NULL == pframe->adsp) {
        DkimStatus adsp_stat = DkimAdsp_lookup(author_domain, self->resolver, &(pframe->adsp));
        switch (adsp_stat) {
        case DSTAT_OK:
            // do nothing
            break;
        case DSTAT_INFO_DNSRR_NXDOMAIN:
            /*
             * A DNS query for Author Domain returns NXDOMAIN error.
             * [RFC5617] 5.4.
             * Code:     nxdomain
             * Meaning:  Evaluating the ADSP for the Author's DNS domain indicated
             *           that the Author's DNS domain does not exist.
             */
            LogInfo("Author domain seems not to exist (NXDOMAIN): domain=%s", author_domain);
            return DKIM_ADSP_SCORE_NXDOMAIN;
        case DSTAT_INFO_DNSRR_NOT_EXIST:
            /*
             * No valid ADSP records are found
             * [RFC5617] 5.4.
             * Code:     none
             * Meaning:  No DKIM Author Domain Signing Practices (ADSP) record was
             *           published.
             */
            LogDebug("no valid DKIM ADSP records are found: domain=%s", author_domain);
            return DKIM_ADSP_SCORE_NONE;
        case DSTAT_PERMFAIL_MULTIPLE_DNSRR:
            /*
             * Multiple ADSP records are found
             * [RFC5617] 5.4.
             * Code:     permerror
             * Meaning:  An ADSP record could not be retrieved due to some error
             *          that is likely not transient in nature, such as a permanent
             *          DNS error.  A later attempt is unlikely to produce a final
             *          result.
             */
            LogInfo("multiple DKIM ADSP records are found: domain=%s", author_domain);
            return DKIM_ADSP_SCORE_PERMERROR;
        case DSTAT_TMPERR_DNS_ERROR_RESPONSE:
        case DSTAT_SYSERR_DNS_LOOKUP_FAILURE:
            /*
             * Temporary DNS error, DNS lookup failure
             * [RFC5617] 5.4.
             * Code:     temperror
             * Meaning:  An ADSP record could not be retrieved due to some error
             *           that is likely transient in nature, such as a temporary DNS
             *           error.  A later attempt may produce a final result.
             */
            LogInfo("DNS lookup error has occurred while retrieving the ADSP record: domain=%s",
                    author_domain);
            return DKIM_ADSP_SCORE_TEMPERROR;
        case DSTAT_SYSERR_NORESOURCE:
            DkimLogSysError("System error occurred while retrieving the ADSP record: domain=%s",
                            author_domain);
            return DKIM_ADSP_SCORE_NULL;
        case DSTAT_SYSERR_IMPLERROR:
        default:
            DkimLogImplError
                ("unexpected error occurred while retrieving the ADSP record: domain=%s, error=%s",
                 author_domain, DkimStatus_getSymbol(adsp_stat));
            return DKIM_ADSP_SCORE_TEMPERROR;
        }   // end switch
    }   // end if

    // log ADSP record
    DkimAdspPractice outbound_practice = DkimAdsp_getPractice(pframe->adsp);
    LogDebug("valid DKIM ADSP record is found: domain=%s, practice=%s",
             author_domain, DkimEnum_lookupPracticeByValue(outbound_practice));

    // determine ADSP score according to outbound signing practice
    switch (outbound_practice) {
    case DKIM_ADSP_PRACTICE_ALL:
        /*
         * [RFC5617] 4.2.1.
         * all       All mail from the domain is signed with an Author
         *           Domain Signature.
         * [RFC5617] 5.4.
         * Code:     fail
         * Meaning:  No valid Author Domain Signature was found on the message
         *           and the published ADSP was "all".
         */
        return DKIM_ADSP_SCORE_FAIL;
    case DKIM_ADSP_PRACTICE_DISCARDABLE:
        /*
         * [RFC5617] 4.2.1.
         * discardable
         *              All mail from the domain is signed with an
         *              Author Domain Signature.  Furthermore, if a
         *              message arrives without a valid Author Domain
         *              Signature due to modification in transit,
         *              submission via a path without access to a
         *              signing key, or any other reason, the domain
         *              encourages the recipient(s) to discard it.
         * [RFC5617] 5.4.
         * Code:     discard
         * Meaning:  No valid Author Domain Signature was found on the message
         *           and the published ADSP was "discardable".
         */
        return DKIM_ADSP_SCORE_DISCARD;
    case DKIM_ADSP_PRACTICE_UNKNOWN:
        /*
         * [RFC5617] 4.2.1.
         * unknown   The domain might sign some or all email.
         * [RFC5617] 5.4.
         * Code:     unknown
         * Meaning:  No valid Author Domain Signature was found on the message
         *           and the published ADSP was "unknown".
         */
        return DKIM_ADSP_SCORE_UNKNOWN;
    case DKIM_ADSP_PRACTICE_NULL:
    default:
        abort();
    }   // end switch
}   // end function: DkimVerifier_evalAdsp

/**
 * perform ADSP and ATPS check.
 * @param self DkimVerifier object
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 */
DkimStatus
DkimVerifier_checkAuthorPolicy(DkimVerifier *self)
{
    assert(NULL != self);

    // minimum initialization
    if (NULL == self->pframe) {
        self->pframe = DkimPolicyFrameArray_new(0);
        if (NULL == self->pframe) {
            LogNoResource();
            return DSTAT_SYSERR_NORESOURCE;
        }   // end if
    }   // end if

    // extract Author
    const InetMailboxArray *authors = NULL;
    HeaderStautus author_stat = InetMailHeaders_extractAuthors(self->headers, &authors);
    switch (author_stat) {
    case HEADER_STAT_OK:
        // author(s) extracted successfully
        assert(NULL != authors);
        break;
    case HEADER_NOT_EXIST:
    case HEADER_NOT_UNIQUE:
    case HEADER_BAD_SYNTAX:;
        /*
         * RFC5322 permits multiple mailboxes in a single "From:" header.
         * And it also defines the number of "From:" header in a single message as 1.
         * So we treat the message with no or multiple "From:" header(s) as "permerror".
         *
         * [RFC5617] 5.4.
         * Code:     permerror
         * Meaning:  An ADSP record could not be retrieved due to some error
         *          that is likely not transient in nature, such as a permanent
         *          DNS error.  A later attempt is unlikely to produce a final
         *          result.
         * [RFC6541] 8.3.
         * Code:  permerror
         * Meaning:  An ATPS evaluation could not be completed due to some error
         *   that is not likely transient in nature, such as a permanent DNS
         *   error.  A later attempt is unlikely to produce a final result.
         */
        DkimPolicyFrame *pframe = DkimPolicyFrameArray_allocate(self->pframe, 0, NULL);
        if (NULL == pframe) {
            LogNoResource();
            return DSTAT_SYSERR_NORESOURCE;
        }   // end if
        pframe->adsp_score = DKIM_ADSP_SCORE_PERMERROR;
        if (self->vpolicy->enable_atps) {
            pframe->atps_score = DKIM_ATPS_SCORE_PERMERROR;
        }   // end if
        return DSTAT_OK;
    case HEADER_NO_RESOURCE:
        LogNoResource();
        return DSTAT_SYSERR_NORESOURCE;
    default:
        abort();
    }   // end switch

    size_t authornum = InetMailboxArray_getCount(authors);
    if (0 < self->vpolicy->author_limit) {
        authornum = MIN(authornum, self->vpolicy->author_limit);
    }   // end if

    for (size_t authoridx = 0; authoridx < authornum; ++authoridx) {
        // avoid re-evaluation
        if (authoridx < DkimPolicyFrameArray_getCount(self->pframe)
            && NULL != DkimPolicyFrameArray_get(self->pframe, authoridx)
            && DKIM_ADSP_SCORE_NULL != DkimPolicyFrameArray_get(self->pframe,
                                                                authoridx)->adsp_score) {
            continue;
        }   // end if

        const InetMailbox *author = InetMailboxArray_get(authors, authoridx);
        DkimPolicyFrame *pframe = DkimPolicyFrameArray_allocate(self->pframe, authoridx, author);
        if (NULL == pframe) {
            LogNoResource();
            return DSTAT_SYSERR_NORESOURCE;
        }   // end if
        const char *author_domain = InetMailbox_getDomain(author);
        if (DkimVerifier_hasAuthorDomainSignature(self, author_domain)) {
            /*
             * Author Domain Signature (= First Party Signature)
             * [RFC5617] 5.4.
             * Code:     pass
             * Meaning:  This message had an Author Domain Signature that was
             *           validated.  (An ADSP check is not strictly required to be
             *           performed for this result since a valid Author Domain
             *           Signature satisfies all possible ADSP policies.)
             */
            pframe->adsp_score = DKIM_ADSP_SCORE_PASS;
            pframe->atps_score = DKIM_ATPS_SCORE_NULL;
            continue;
        }   // end if

        if (self->have_temporary_error || self->have_system_error) {
            // SPEC: dkim-adsp score on system error is "temperror"
            pframe->adsp_score = DKIM_ADSP_SCORE_TEMPERROR;
            if (self->vpolicy->enable_atps) {
                pframe->atps_score = DKIM_ATPS_SCORE_TEMPERROR;
            }   // end if
            continue;
        }   // end if

        /*
         * [RFC6541] 6.
         * A Verifier implementing both Author Domain Signing Practices (ADSP)
         * and ATPS MUST test ATPS first.
         *
         * But we evaluate both regardless of where ATPS indicates a valid delegation.
         * And the evaluation of ADSP here does not consider the result of ATPS at all.
         * So the order of evaluation has no meaning here.
         */
        pframe->atps_score =
            self->vpolicy->enable_atps ? DkimVerifier_evalAtps(self, author_domain) :
            DKIM_ATPS_SCORE_NULL;
        pframe->adsp_score = DkimVerifier_evalAdsp(self, author_domain, pframe);
    }   // end for

    return DSTAT_OK;
}   // end function: DkimVerifier_checkAuthorPolicy

/**
 * return the number of DKIM signatures targeted to verify.
 * in other words, the number of DKIM verification frames.
 * @param self DkimVerifier object
 * @return the number of DKIM signatures targeted to verify.
 */
size_t
DkimVerifier_getFrameCount(const DkimVerifier *self)
{
    assert(NULL != self);
    return DkimVerificationFrameArray_getCount(self->vframe);
}   // end function: DkimVerifier_getFrameCount

/**
 * return the result of specified verification frame.
 * @param self DkimVerifier object
 */
const DkimFrameResult *
DkimVerifier_getFrameResult(const DkimVerifier *self, size_t signo)
{
    // XXX まだ検証が終わっていない状態をエラーとして想定していない!
    assert(NULL != self);

    size_t framenum = DkimVerificationFrameArray_getCount(self->vframe);
    DkimVerificationFrame *frame = DkimVerificationFrameArray_get(self->vframe, signo);

    if (signo < framenum) {
        DkimVerificationFrame_buildResult(frame);
        return &frame->result;
    } else if (signo < self->sigheader_num) {
        /*
         * SPEC: dkim score is "policy" if the number of DKIM-Signature header exceeds
         * its limit specified by DkimVerificationPolicy.
         *
         * [RFC5451] 2.4.1.
         * policy:  The message was signed but the signature or signatures were
         *    not acceptable to the verifier.
         */
        return &toomany_sig_result;
    } else {
        abort();
    }   // end if
}   // end function: DkimVerifier_getFrameResult

/**
 * @attention must be called after DkimVerifier_checkAuthorPolicy()
 */
size_t
DkimVerifier_getPolicyFrameCount(const DkimVerifier *self)
{
    assert(NULL != self);
    return DkimPolicyFrameArray_getCount(self->pframe);
}   // end function: DkimVerifier_getPolicyFrameCount

/**
 * @attention must be called after DkimVerifier_checkAuthorPolicy()
 */
bool
DkimVerifier_getPolicyFrameResult(const DkimVerifier *self, size_t author_idx,
                                  const InetMailbox **author, DkimAdspScore *adsp_score,
                                  DkimAtpsScore *atps_score)
{
    assert(NULL != self);
    assert(NULL != author);

    size_t framenum = DkimPolicyFrameArray_getCount(self->pframe);
    if (author_idx < framenum) {
        DkimPolicyFrame *frame = DkimPolicyFrameArray_get(self->pframe, author_idx);
        *author = frame->author;
        SETDEREF(adsp_score, frame->adsp_score);
        SETDEREF(atps_score, frame->atps_score);
        return true;
    } else {
        return false;
    }   // end if
}   // end function: DkimVerifier_getPolicyFrameResult

/**
 * @param self DkimVerifier object
 * @attention for debugging use only.
 * @attention must be called after DkimVerifier_setup() and before the first call of DkimVerifier_updateBody()
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 */
DkimStatus
DkimVerifier_enableC14nDump(DkimVerifier *self, const char *basedir, const char *prefix)
{
    assert(NULL != self);

    if (DSTAT_OK != self->status) {
        // do nothing
        return DSTAT_OK;
    }   // end if

    // Canonicalized messages vary from one DKIM-Signature header to another.
    // So canonicalized messages should be dumped for every verification frame.
    size_t framenum = DkimVerificationFrameArray_getCount(self->vframe);
    for (size_t frameidx = 0; frameidx < framenum; ++frameidx) {
        DkimVerificationFrame *frame = DkimVerificationFrameArray_get(self->vframe, frameidx);
        char header_filename[MAXPATHLEN];
        char body_filename[MAXPATHLEN];

        if (DSTAT_OK != frame->status) {
            continue;
        }   // end if
        snprintf(header_filename, MAXPATHLEN, "%s/%s.%02zu.header", basedir, prefix, frameidx);
        snprintf(body_filename, MAXPATHLEN, "%s/%s.%02zu.body", basedir, prefix, frameidx);

        DkimStatus open_stat =
            DkimDigester_enableC14nDump(frame->digester, header_filename, body_filename);
        if (DSTAT_OK != open_stat) {
            return open_stat;
        }   // end if
    }   // end for
    return DSTAT_OK;
}   // end function: DkimVerifier_enableC14nDump
