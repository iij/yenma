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
#include <errno.h>
#include <time.h>
#include <sys/param.h>

#include "dkimlogger.h"
#include "strarray.h"
#include "inetmailheaders.h"
#include "ptrop.h"
#include "inetdomain.h"
#include "inetmailbox.h"
#include "dkim.h"
#include "dkimdigester.h"
#include "dkimsignpolicy.h"

struct DkimSigner {
    const DkimSignPolicy *spolicy;
    DkimStatus status;
    const InetMailHeaders *headers;

    DkimDigester *digester;
    DkimSignature *signature;
};

/**
 * release DkimSigner object
 * @param self DkimSigner object to be released
 */
void
DkimSigner_free(DkimSigner *self)
{
    if (NULL == self) {
        return;
    }   // end if

    DkimSignature_free(self->signature);
    DkimDigester_free(self->digester);
    free(self);
}   // end function: DkimSigner_free

/**
 * @param spolicy DkimSignPolicy object to be associated with the created DkimSigner object.
 *                This object can be shared between multiple threads.
 * @param auid mail address to be used as AUID
 * @param sdid domain name to be used as SDID
 * @param headers InetMailHeaders object that stores all headers to be signed with DKIM.
 *                Key of InetMailHeaders object is treated as header field name excepting ':'.
 *                Value of InetMailHeaders object is treated as header field value excepting ':',
 *                and it is switchable by keep_leading_header_space
 *                whether or not SP (space) character after ':' is included in header field values.
 *                (sendmail 8.13 or earlier does not include SP in header field value,
 *                sendmail 8.14 or later with SMFIP_HDR_LEADSPC includes it.)
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 * @error DSTAT_SYSERR_IMPLERROR obvious implementation error
 * @error DSTAT_PERMFAIL_UNSUPPORTED_HASH_ALGORITHM unsupported digest algorithm
 * @error DSTAT_PERMFAIL_UNSUPPORTED_KEY_ALGORITHM unsupported public key algorithm
 */
DkimStatus
DkimSigner_new(const DkimSignPolicy *spolicy, const InetMailbox *auid, const char *sdid,
               const char *atps_domain, const InetMailHeaders *headers,
               const StrArray *signed_header_fields, bool keep_leading_header_space,
               DkimSigner **signer)
{
    assert(NULL != spolicy);
    assert(NULL != auid || NULL != sdid);
    assert(NULL != headers);

    DkimSigner *self = (DkimSigner *) malloc(sizeof(DkimSigner));
    if (NULL == self) {
        LogNoResource();
        return DSTAT_SYSERR_NORESOURCE;
    }   // end if
    memset(self, 0, sizeof(DkimSigner));

    // minimum initialization
    self->signature = DkimSignature_new();
    if (NULL == self->signature) {
        LogNoResource();
        DkimSigner_free(self);
        return DSTAT_SYSERR_NORESOURCE;
    }   // end if

    self->spolicy = spolicy;
    self->headers = headers;

    // get time to use as signature timestamp (sig-t-tag)
    time_t epoch;
    if (0 > time(&epoch)) {
        DkimLogSysError("time(2) failed: errno=%s", strerror(errno));
        DkimSigner_free(self);
        return DSTAT_SYSERR_IMPLERROR;
    }   // end if

    // construct and configure DkimSignature object
    DkimSignature_setHashAlgorithm(self->signature, spolicy->hashalg);
    DkimSignature_setKeyType(self->signature, spolicy->keytype);
    DkimSignature_setHeaderC14nAlgorithm(self->signature, spolicy->canon_method_header);
    DkimSignature_setBodyC14nAlgorithm(self->signature, spolicy->canon_method_body);
    DkimSignature_setBodyLengthLimit(self->signature, -1LL);    // disable body length limit explicitly

    // set SDID (sig-d-tag)
    DkimStatus sdid_stat =
        DkimSignature_setSdid(self->signature, PTROR(sdid, InetMailbox_getDomain(auid)));
    if (DSTAT_OK != sdid_stat) {
        DkimSigner_free(self);
        return sdid_stat;
    }   // end if

    // set AUID (sig-i-tag)
    if (NULL != auid) {
        DkimStatus auid_stat = DkimSignature_setAuid(self->signature, auid);
        if (DSTAT_OK != auid_stat) {
            DkimSigner_free(self);
            return auid_stat;
        }   // end if
    }   // end if

    DkimSignature_setTimestamp(self->signature, (long long) epoch);
    DkimSignature_setTTL(self->signature, spolicy->signature_ttl);

    // enable DKIM-ATPS
    if (NULL != atps_domain) {
        DkimStatus atps_stat = DkimSignature_setAtpsDomain(self->signature, atps_domain);
        if (DSTAT_OK != atps_stat) {
            DkimSigner_free(self);
            return atps_stat;
        }   // end if
        DkimSignature_setAtpsHashAlgorithm(self->signature, spolicy->atps_hashalg);
    }   // end if

    if (NULL != signed_header_fields) {
        DkimStatus set_stat =
            DkimSignature_setSignedHeaderFields(self->signature, signed_header_fields);
        if (DSTAT_OK != set_stat) {
            DkimSigner_free(self);
            return set_stat;
        }   // end if
    } else {
        size_t headernum = InetMailHeaders_getCount(self->headers);
        for (size_t headeridx = 0; headeridx < headernum; ++headeridx) {
            const char *headerf, *headerv;
            InetMailHeaders_get(self->headers, headeridx, &headerf, &headerv);
            if (NULL == headerf || NULL == headerv) {
                LogWarning("ignore an invalid header: no=%zd, name=%s, value=%s",
                           headeridx, NNSTR(headerf), NNSTR(headerv));
                continue;
            }   // end if

            // register all headers to be signed with DKIM stored in "headers"
            DkimStatus add_stat = DkimSignature_addSignedHeaderField(self->signature, headerf);
            if (DSTAT_OK != add_stat) {
                DkimSigner_free(self);
                return add_stat;
            }   // end if
        }   // end for
    }   // end if

    DkimStatus digest_stat =
        DkimDigester_newWithSignature(self->signature, keep_leading_header_space,
                                      &(self->digester));
    if (DSTAT_OK != digest_stat) {
        if (DSTAT_ISCRITERR(digest_stat)) {
            DkimSigner_free(self);
            return digest_stat;
        } else {
            *signer = self;
            return self->status = digest_stat;
        }   // end if
    }   // end if

    *signer = self;
    return self->status = DSTAT_OK;
}   // end function: DkimSigner_new

/**
 * @param self DkimSigner object
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 * @error DSTAT_SYSERR_IMPLERROR obvious implementation error
 * @error DSTAT_SYSERR_DIGEST_UPDATE_FAILURE error on digest update (returned by OpenSSL EVP_DigestUpdate())
 */
DkimStatus
DkimSigner_updateBody(DkimSigner *self, const unsigned char *bodyp, size_t len)
{
    assert(NULL != self);

    if (DSTAT_OK != self->status) {
        // do nothing
        return DSTAT_OK;
    }   // end if

    self->status = DkimDigester_updateBody(self->digester, bodyp, len);
    return self->status;
}   // end function: DkimSigner_updateBody

/**
 * finalize message body update, and generate the DKIM-Signature header.
 * @param self DkimSigner object
 * @param selector selector
 * @param pkey private key
 * @param prepend_space whether or not to prepend a SP to the DKIM Signature value (headerf).
 *                This flag is independent from keep_leading_header_space parameter passed in DkimSigner_setup().
 * @param headerf a pointer to a variable to receive the header field name.
 *                Buffer is allocated inside the DkimSigner object
 *                and is available until destruction of the DkimSigner object.
 *                "DKIM-Signature" is returned normally.
 * @param headerv a pointer to a variable to receive the header field value.
 *                Buffer is allocated inside the DkimSigner object
 *                and is available until destruction of the DkimSigner object.
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 * @error DSTAT_SYSERR_IMPLERROR obvious implementation error
 * @error DSTAT_SYSERR_DIGEST_UPDATE_FAILURE error on digest update (returned by OpenSSL EVP_DigestUpdate())
 */
DkimStatus
DkimSigner_sign(DkimSigner *self, const char *selector, EVP_PKEY *privatekey, bool prepend_space,
                const char **headerf, const char **headerv)
{
    assert(NULL != self);
    assert(NULL != selector);
    assert(NULL != privatekey);

    if (DSTAT_OK != self->status) {
        return self->status;    // return status code if an error occurred
    }   // end if

    DkimStatus ret = DkimSignature_setSelector(self->signature, selector);
    if (DSTAT_OK != ret) {
        self->status = ret;
        return self->status;
    }   // end if

    ret = DkimDigester_signMessage(self->digester, self->headers, self->signature, privatekey);
    if (DSTAT_OK != ret) {
        self->status = ret;
        return self->status;
    }   // end if
    self->status =
        DkimSignature_buildRawHeader(self->signature, false, self->spolicy->sign_header_with_crlf,
                                     prepend_space, headerf, headerv);
    return self->status;
}   // end function: DkimSigner_sign

/**
 * @param self DkimSigner object
 * @attention for debugging use only.
 * @attention must be called after DkimSigner_setup() and before the first call of DkimSigner_updateBody()
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 */
DkimStatus
DkimSigner_enableC14nDump(DkimSigner *self, const char *basedir, const char *prefix)
{
    assert(NULL != self);

    if (DSTAT_OK != self->status) {
        // do nothing
        return DSTAT_OK;
    }   // end if

    char header_filename[MAXPATHLEN];
    char body_filename[MAXPATHLEN];

    snprintf(header_filename, MAXPATHLEN, "%s/%s.header", basedir, prefix);
    snprintf(body_filename, MAXPATHLEN, "%s/%s.body", basedir, prefix);
    return DkimDigester_enableC14nDump(self->digester, header_filename, body_filename);
}   // end function: DkimSigner_enableC14nDump
