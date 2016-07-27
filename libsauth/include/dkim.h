/*
 * Copyright (c) 2006-2016 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifndef __DKIM_H__
#define __DKIM_H__

#include <sys/types.h>
#include <stdbool.h>
#include <openssl/evp.h>

#include "dnsresolv.h"
#include "inetmailbox.h"
#include "inetmailheaders.h"
#include "strarray.h"

#ifdef __cplusplus
extern "C" {
#endif

// Enumerations
typedef enum DkimBaseScore {
    DKIM_BASE_SCORE_NULL = 0,
    DKIM_BASE_SCORE_NONE,
    DKIM_BASE_SCORE_PASS,
    DKIM_BASE_SCORE_FAIL,
    DKIM_BASE_SCORE_POLICY,
    DKIM_BASE_SCORE_NEUTRAL,
    DKIM_BASE_SCORE_TEMPERROR,
    DKIM_BASE_SCORE_PERMERROR,
    DKIM_BASE_SCORE_MAX,    // the number of DkimBaseScore enumeration constants
} DkimBaseScore;

typedef enum DkimAdspScore {
    DKIM_ADSP_SCORE_NULL = 0,
    DKIM_ADSP_SCORE_NONE,
    DKIM_ADSP_SCORE_PASS,
    DKIM_ADSP_SCORE_UNKNOWN,
    DKIM_ADSP_SCORE_FAIL,
    DKIM_ADSP_SCORE_DISCARD,
    DKIM_ADSP_SCORE_NXDOMAIN,
    DKIM_ADSP_SCORE_TEMPERROR,
    DKIM_ADSP_SCORE_PERMERROR,
    DKIM_ADSP_SCORE_MAX,    // the number of DkimAdspScore enumeration constants
} DkimAdspScore;

typedef enum DkimAtpsScore {
    DKIM_ATPS_SCORE_NULL = 0,
    DKIM_ATPS_SCORE_NONE,
    DKIM_ATPS_SCORE_PASS,
    DKIM_ATPS_SCORE_FAIL,
    DKIM_ATPS_SCORE_TEMPERROR,
    DKIM_ATPS_SCORE_PERMERROR,
    DKIM_ATPS_SCORE_MAX,    // the number of DkimAtpsScore enumeration constants
} DkimAtpsScore;

#define DSTAT_CATMASK       0xff00
#define DSTATCAT_OK         0x0000
#define DSTATCAT_INFO       0x0100
#define DSTATCAT_SYSERR     0x0200
#define DSTATCAT_TMPERR     0x0300
#define DSTATCAT_PERMFAIL   0x0400
#define DSTATCAT_POLICY     0x0500
#define DSTATCAT_CFGERR     0x0600
#define DSTATCAT_WARN       0x0700

#define DSTAT_ISOK(__e)         (((__e) & DSTAT_CATMASK) == DSTATCAT_OK)
#define DSTAT_ISINFO(__e)       (((__e) & DSTAT_CATMASK) == DSTATCAT_INFO)
#define DSTAT_ISSYSERR(__e)     (((__e) & DSTAT_CATMASK) == DSTATCAT_SYSERR)
#define DSTAT_ISTMPERR(__e)     (((__e) & DSTAT_CATMASK) == DSTATCAT_TMPERR)
#define DSTAT_ISPERMFAIL(__e)   (((__e) & DSTAT_CATMASK) == DSTATCAT_PERMFAIL)
#define DSTAT_ISPOLICY(__e)     (((__e) & DSTAT_CATMASK) == DSTATCAT_POLICY)
#define DSTAT_ISCFGERR(__e)     (((__e) & DSTAT_CATMASK) == DSTATCAT_CFGERR)
#define DSTAT_ISWARN(__e)       (((__e) & DSTAT_CATMASK) == DSTATCAT_WARN)
#define DSTAT_ISCRITERR(__e)    (DSTAT_ISSYSERR(__e) || DSTAT_ISCFGERR(__e))

// Status Codes
typedef enum DkimStatus {
    DSTAT_OK = DSTATCAT_OK,
    DSTAT_INFO_DIGEST_MATCH = DSTATCAT_INFO,    // the digest value of message header fields and body matches
    DSTAT_INFO_FINISHED,
    DSTAT_INFO_DNSRR_NOT_EXIST, // DNS RR not found
    DSTAT_INFO_DNSRR_NXDOMAIN,  // DNS RR does not exist (NXDOMAIN)
    DSTAT_INFO_NO_SIGNHEADER,   // No DKIM-Signature headers are found
    // [System Errors]
    DSTAT_SYSERR_DIGEST_UPDATE_FAILURE = DSTATCAT_SYSERR,   // error on digest update (returned by OpenSSL EVP_DigestUpdate())
    DSTAT_SYSERR_DIGEST_VERIFICATION_FAILURE,   // error on digital signature verification (returned by OpenSSL EVP_VerifyFinal())
    DSTAT_SYSERR_IO_ERROR,  // I/O error
    DSTAT_SYSERR_IMPLERROR, // obvious implementation error
    DSTAT_SYSERR_NORESOURCE,    // memory allocation error
    DSTAT_SYSERR_DNS_LOOKUP_FAILURE,    // DNS lookup error (failed to lookup itself)
    // [Temporary Errors]
    DSTAT_TMPERR_DNS_ERROR_RESPONSE = DSTATCAT_TMPERR,  // DNS lookup error (received error response)
    // [DKIM signature verification/generation failures]
    // verification errors
    DSTAT_PERMFAIL_SIGNATURE_DID_NOT_VERIFY = DSTATCAT_PERMFAIL,    // the digest value of the message header fields does not match
    DSTAT_PERMFAIL_BODY_HASH_DID_NOT_VERIFY,    // the digest value of the message body does not match
    DSTAT_PERMFAIL_NO_AUTHOR_HEADER,    // No Author header is found
    DSTAT_PERMFAIL_MULTIPLE_AUTHOR_HEADERS, // multiple Author headers are found
    DSTAT_PERMFAIL_AUTHOR_UNPARSABLE,   // unable to parse Author header field value
    // tag-value object errors
    DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION,    // generic tag-value syntax violation
    DSTAT_PERMFAIL_MISSING_REQUIRED_TAG,    // missing required tag
    DSTAT_PERMFAIL_TAG_DUPLICATED,  // multiple identical tags are found
    DSTAT_PERMFAIL_UNSUPPORTED_KEY_ALGORITHM,   // unsupported public key algorithm
    DSTAT_PERMFAIL_INCOMPATIBLE_RECORD_VERSION, // unsupported record version
    // Signature errors
    DSTAT_PERMFAIL_SIGNATURE_SYNTAX_VIOLATION,  // tag-value syntax violation in the signature
    DSTAT_PERMFAIL_SIGNATURE_INCOMPATIBLE_VERSION,  // unsupported signature version
    DSTAT_PERMFAIL_DOMAIN_MISMATCH, // domains are not matched between sig-i-tag and sig-d-tag
    DSTAT_PERMFAIL_FROM_FIELD_NOT_SIGNED,   // "From:" header header is not signed
    DSTAT_PERMFAIL_SIGNATURE_EXPIRED,   // DKIM-Signature has expired
    DSTAT_PERMFAIL_INCONSISTENT_TIMESTAMP,  // timestamp of sig-t-tag is later than sig-x-tag
    DSTAT_PERMFAIL_UNSUPPORTED_C14N_ALGORITHM,  // unsupported canonicalization algorithm
    DSTAT_PERMFAIL_UNSUPPORTED_QUERY_METHOD,    // unsupported query method to retrieve public key
    DSTAT_PERMFAIL_UNSUPPORTED_HASH_ALGORITHM,  // unsupported digest algorithm
    // Public key errors
    DSTAT_PERMFAIL_KEY_SYNTAX_VIOLATION,    // tag-value syntax violation in the public key
    DSTAT_PERMFAIL_NO_KEY_FOR_SIGNATURE,    // Public key record does not exist
    DSTAT_PERMFAIL_KEY_REVOKED, // Public key record has revoked
    DSTAT_PERMFAIL_KEY_TOO_WEAK,        // the signing key is weaker than verifier policy
    DSTAT_PERMFAIL_INCOMPATIBLE_KEY_VERSION,    // unsupported public key version
    DSTAT_PERMFAIL_INAPPROPRIATE_SERVICE_TYPE,  // service type dose not allow the public key record to be applied to email
    DSTAT_PERMFAIL_INAPPROPRIATE_HASH_ALGORITHM,    // digest algorithm of the public key record (key-h-tag) does not match the one of the signature (sig-a-tag-h)
    DSTAT_PERMFAIL_INAPPROPRIATE_KEY_ALGORITHM, // public key algorithm of the public key record (key-k-tag) does not match the one of the signature (sig-a-tag-k)
    DSTAT_PERMFAIL_INAPPLICABLE_KEY,    // the local-part of "i=" tag of the signature (sig-i-tag) does not match the granularity of the public key record (key-g-tag)
    DSTAT_PERMFAIL_PUBLICKEY_TYPE_MISMATCH, // key-k-tag and the content of public key (key-p-tag) does not matched
    DSTAT_PERMFAIL_PUBLICKEY_SUBDOMAIN_PROHIBITED,  // public key record does not accept subdomain
    DSTAT_PERMFAIL_PUBLICKEY_BROKEN,    // Public key is broken (returned by OpenSSL d2i_PUBKEY())
    // ADSP errors
    DSTAT_PERMFAIL_MULTIPLE_DNSRR,  // multiple DNS RR records are found
    // [Policy Violation]
    DSTAT_POLICY_TOOMANY_SIGNATURES = DSTATCAT_POLICY,  // too many signatures in a single message
    // [Misconfigurations]
    DSTAT_CFGERR_SYNTAX_VIOLATION = DSTATCAT_CFGERR,    // syntax error at configuration directives
    DSTAT_CFGERR_EMPTY_VALUE,   // empty value or NULL is specified for configuration
    DSTAT_CFGERR_UNDEFINED_KEYWORD, // undefined keyword is specified for configuration
    DSTAT_CFGERR_FILE_NOT_FOUND,    // specified file does not exist
    // [Warnings]
    DSTAT_WARN_CANONDUMP_OPEN_FAILURE = DSTATCAT_WARN,  // failed to open files to debug
    DSTAT_WARN_CANONDUMP_UPDATE_FAILURE,    // an error on dumping canonicalized text data
} DkimStatus;

// type declarations
typedef struct DkimVerificationPolicy DkimVerificationPolicy;
typedef struct DkimVerifier DkimVerifier;
typedef struct DkimSignPolicy DkimSignPolicy;
typedef struct DkimSigner DkimSigner;
typedef struct DkimFrameResult {
    DkimBaseScore score;
    DkimStatus stauts;
    bool testing;
    const char *sdid;
    const InetMailbox *auid;
    int pkey_bits;
} DkimFrameResult;

// DkimVerificationPolicy
extern DkimVerificationPolicy *DkimVerificationPolicy_new(void);
extern void DkimVerificationPolicy_free(DkimVerificationPolicy *self);
extern void DkimVerificationPolicy_setSignHeaderLimit(DkimVerificationPolicy *self,
		                                              unsigned int header_limit);
extern void DkimVerificationPolicy_setAuthorLimit(DkimVerificationPolicy *self,
                                                  size_t author_limit);
extern void DkimVerificationPolicy_acceptExpiredSignature(DkimVerificationPolicy *self, bool flag);
extern void DkimVerificationPolicy_acceptFutureSignature(DkimVerificationPolicy *self, bool flag);
extern void DkimVerificationPolicy_verifyAtpsDelegation(DkimVerificationPolicy *self, bool flag);
extern void DkimVerificationPolicy_setRfc4871Compatible(DkimVerificationPolicy *self, bool enable);
extern void DkimVerificationPolicy_setMinRSAKeyLength(DkimVerificationPolicy *self, unsigned int keylen);
extern void DkimVerificationPolicy_setMaxClockSkew(DkimVerificationPolicy *self, time_t skew);

// DkimVerifier
extern void DkimVerifier_free(DkimVerifier *self);
extern DkimStatus DkimVerifier_new(const DkimVerificationPolicy *vpolicy, DnsResolver *resolver,
                                   const InetMailHeaders *headers, bool keep_leading_header_space,
                                   DkimVerifier **verifier);
extern DkimStatus DkimVerifier_updateBody(DkimVerifier *self, const unsigned char *bodyp,
                                          size_t len);
extern DkimStatus DkimVerifier_verify(DkimVerifier *self);
extern DkimStatus DkimVerifier_enableC14nDump(DkimVerifier *self, const char *basedir,
                                              const char *prefix);
extern size_t DkimVerifier_getFrameCount(const DkimVerifier *self);
extern DkimBaseScore DkimVerifier_getSessionResult(const DkimVerifier *self);
extern const DkimFrameResult *DkimVerifier_getFrameResult(const DkimVerifier *self, size_t signo);
extern size_t DkimVerifier_getPolicyFrameCount(const DkimVerifier *self);
extern bool DkimVerifier_getPolicyFrameResult(const DkimVerifier *self, size_t author_idx,
                                              const InetMailbox **author,
                                              DkimAdspScore *adsp_score, DkimAtpsScore *atps_score);
extern DkimStatus DkimVerifier_checkAuthorPolicy(DkimVerifier *self);

// DkimSignPolicy
extern DkimSignPolicy *DkimSignPolicy_new(void);
extern void DkimSignPolicy_free(DkimSignPolicy *self);
extern DkimStatus DkimSignPolicy_setCanonAlgorithm(DkimSignPolicy *self,
                                                   const char *headercanon, const char *bodycanon);
extern DkimStatus DkimSignPolicy_setHashAlgorithm(DkimSignPolicy *self, const char *digestalg);
extern DkimStatus DkimSignPolicy_setAtpsHashAlgorithm(DkimSignPolicy *self,
                                                      const char *atps_hashalg);
extern DkimStatus DkimSignPolicy_setKeyType(DkimSignPolicy *self, const char *pubkeyalg);
extern void DkimSignPolicy_setSignatureTTL(DkimSignPolicy *self, long long signature_ttl);
extern void DkimSignPolicy_setNewlineCharOfSignature(DkimSignPolicy *self, bool crlf);

// DkimSigner
extern void DkimSigner_free(DkimSigner *self);
extern DkimStatus DkimSigner_new(const DkimSignPolicy *spolicy, const InetMailbox *auid,
                                 const char *sdid, const char *atps_domain,
                                 const InetMailHeaders *headers,
                                 const StrArray *signed_header_fields,
                                 bool keep_leading_header_space, DkimSigner **signer);
extern DkimStatus DkimSigner_updateBody(DkimSigner *self, const unsigned char *bodyp, size_t len);
extern DkimStatus DkimSigner_sign(DkimSigner *self, const char *selector, EVP_PKEY *pkey,
                                  bool prepend_space, const char **headerf, const char **headerv);
extern DkimStatus DkimSigner_enableC14nDump(DkimSigner *self, const char *basedir,
                                            const char *prefix);

extern const char *DkimStatus_getSymbol(DkimStatus code);
extern const char *DkimStatus_strerror(DkimStatus code);
extern const char *DkimEnum_lookupScoreByValue(DkimBaseScore val);
extern DkimBaseScore DkimEnum_lookupScoreByName(const char *keyword);
extern DkimBaseScore DkimEnum_lookupScoreByNameSlice(const char *head, const char *tail);

extern const char *DkimEnum_lookupAdspScoreByValue(DkimAdspScore val);
extern DkimAdspScore DkimEnum_lookupAdspScoreByName(const char *keyword);
extern DkimAdspScore DkimEnum_lookupAdspScoreByNameSlice(const char *head, const char *tail);

extern DkimAtpsScore DkimEnum_lookupAtpsScoreByName(const char *keyword);
extern DkimAtpsScore DkimEnum_lookupAtpsScoreByNameSlice(const char *head, const char *tail);
extern const char *DkimEnum_lookupAtpsScoreByValue(DkimAtpsScore value);

#ifdef __cplusplus
}
#endif
#endif // __DKIM_H__
