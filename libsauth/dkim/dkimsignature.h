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

#ifndef __DKIM_SIGNATURE_H__
#define __DKIM_SIGNATURE_H__

#include "strarray.h"
#include "xbuffer.h"
#include "intarray.h"
#include "dkim.h"
#include "dkimenum.h"
#include "inetmailbox.h"
#include "dkimtaglistobject.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct DkimSignature DkimSignature;

extern DkimSignature *DkimSignature_new(void);
extern DkimStatus DkimSignature_isExpired(const DkimSignature *self);
extern DkimStatus DkimSignature_checkFutureTimestamp(const DkimSignature *self);
extern DkimStatus DkimSignature_build(const char *headerf,
                                      const char *headerv, DkimSignature **signature);
extern void DkimSignature_free(DkimSignature *self);
extern DkimStatus DkimSignature_buildRawHeader(DkimSignature *self, bool digestmode, bool crlf,
                                               bool prepend_space, const char **rawheaderf,
                                               const char **rawheaderv);
extern DkimStatus DkimSignature_addSignedHeaderField(DkimSignature *self, const char *headerf);
extern bool DkimSignature_isHeaderSigned(const DkimSignature *self, const char *headerf);
extern const char *DkimSignature_getSdid(const DkimSignature *self);
extern DkimStatus DkimSignature_setSdid(DkimSignature *self, const char *domain);
extern const char *DkimSignature_getSelector(const DkimSignature *self);
extern DkimStatus DkimSignature_setSelector(DkimSignature *self, const char *selector);
extern DkimHashAlgorithm DkimSignature_getHashAlgorithm(const DkimSignature *self);
extern void DkimSignature_setHashAlgorithm(DkimSignature *self, DkimHashAlgorithm digestalg);
extern DkimKeyType DkimSignature_getKeyType(const DkimSignature *self);
extern void DkimSignature_setKeyType(DkimSignature *self, DkimKeyType pubkeyalg);
extern long long DkimSignature_getTimestamp(const DkimSignature *self);
extern void DkimSignature_setTimestamp(DkimSignature *self, long long genaratetime);
extern long long DkimSignature_getExpirationDate(const DkimSignature *self);
extern void DkimSignature_setExpirationDate(DkimSignature *self, long long expiration_date);
extern long long DkimSignature_setTTL(DkimSignature *self, long long valid_period);
extern const XBuffer *DkimSignature_getSignatureValue(const DkimSignature *self);
extern DkimStatus DkimSignature_setSignatureValue(DkimSignature *self,
                                                  unsigned char *hashbuf, unsigned int hashlen);
extern const XBuffer *DkimSignature_getBodyHash(const DkimSignature *self);
extern DkimStatus DkimSignature_setBodyHash(DkimSignature *self,
                                            unsigned char *hashbuf, unsigned int hashlen);
extern const StrArray *DkimSignature_getSignedHeaderFields(const DkimSignature *self);
extern DkimStatus DkimSignature_setSignedHeaderFields(DkimSignature *self,
                                                      const StrArray *signed_header_fields);
extern DkimC14nAlgorithm DkimSignature_getHeaderC14nAlgorithm(const DkimSignature *self);
extern void DkimSignature_setHeaderC14nAlgorithm(DkimSignature *self,
                                                 DkimC14nAlgorithm headercanon);
extern DkimC14nAlgorithm DkimSignature_getBodyC14nAlgorithm(const DkimSignature *self);
extern void DkimSignature_setBodyC14nAlgorithm(DkimSignature *self, DkimC14nAlgorithm bodycanon);
extern long long DkimSignature_getBodyLengthLimit(const DkimSignature *self);
extern void DkimSignature_setBodyLengthLimit(DkimSignature *self, long long body_length_limit);
extern const char *DkimSignature_getRawHeaderName(const DkimSignature *self);
extern const char *DkimSignature_getRawHeaderValue(const DkimSignature *self);
extern void DkimSignature_getReferenceToBodyHashOfRawHeaderValue(const DkimSignature *self,
                                                                 const char **head,
                                                                 const char **tail);
extern const InetMailbox *DkimSignature_getAuid(const DkimSignature *self);
extern DkimStatus DkimSignature_setAuid(DkimSignature *self, const InetMailbox *mailbox);
extern const IntArray *DkimSignature_getQueryMethod(const DkimSignature *self);
extern const char *DkimSignature_getAtpsDomain(const DkimSignature *self);
extern DkimStatus DkimSignature_setAtpsDomain(DkimSignature *self, const char *atps_domain);
extern DkimHashAlgorithm DkimSignature_getAtpsHashAlgorithm(const DkimSignature *self);
extern void DkimSignature_setAtpsHashAlgorithm(DkimSignature *self, DkimHashAlgorithm atps_hashalg);

#ifdef __cplusplus
}
#endif

#endif /* __DKIM_SIGNATURE_H__ */
