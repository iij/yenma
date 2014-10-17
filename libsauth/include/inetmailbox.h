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

#ifndef __INET_MAILBOX_H__
#define __INET_MAILBOX_H__

#include <stdbool.h>
#include "xbuffer.h"
#include "ptrarray.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct InetMailbox InetMailbox;

typedef InetMailbox *(*InetMailbox_builder) (const char *head, const char *tail, const char **nextp,
                                             const char **errptr);

extern InetMailbox *InetMailbox_buildWithLength(const char *localpart, size_t localpart_len,
                                                const char *domain, size_t domain_len);
extern InetMailbox *InetMailbox_build(const char *localpart, const char *domain);
extern InetMailbox *InetMailbox_duplicate(const InetMailbox *mailbox);
extern InetMailbox *InetMailbox_buildDkimIdentity(const char *head, const char *tail,
                                                  const char **nextp, const char **errptr);
extern InetMailbox *InetMailbox_build2821Mailbox(const char *head, const char *tail,
                                                 const char **nextp, const char **errptr);
extern InetMailbox *InetMailbox_build2821Path(const char *head, const char *tail,
                                              const char **nextp, const char **errptr);
extern InetMailbox *InetMailbox_build2821ReversePath(const char *head, const char *tail,
                                                     const char **nextp, const char **errptr);
extern InetMailbox *InetMailbox_build2822Mailbox(const char *head, const char *tail,
                                                 const char **nextp, const char **errptr);
extern const char *InetMailbox_getLocalPart(const InetMailbox *self);
extern const char *InetMailbox_getDomain(const InetMailbox *self);
extern bool InetMailbox_isNullAddr(const InetMailbox *self);
extern void InetMailbox_free(InetMailbox *self);
extern size_t InetMailbox_getRawAddrLength(const InetMailbox *self);
extern int InetMailbox_writeRawAddr(const InetMailbox *self, XBuffer *xbuf);
extern bool InetMailbox_isLocalPartQuoted(const InetMailbox *self);
extern int InetMailbox_writeAddrSpec(const InetMailbox *self, XBuffer *xbuf);
extern int InetMailbox_writeMailbox(const InetMailbox *self, XBuffer *xbuf);

extern InetMailbox *InetMailbox_buildSendmailPath(const char *head, const char *tail,
                                                  const char **nextp, const char **errptr);
extern InetMailbox *InetMailbox_buildSendmailReversePath(const char *head, const char *tail,
                                                         const char **nextp, const char **errptr);
extern InetMailbox *InetMailbox_buildSmtpPath(const char *head, const char *tail,
                                              const char **nextp, const char **errptr);
extern InetMailbox *InetMailbox_buildSmtpReversePath(const char *head, const char *tail,
                                                     const char **nextp, const char **errptr);

typedef PtrArray InetMailboxArray;
extern InetMailboxArray *InetMailboxArray_new(size_t size);
extern int InetMailboxArray_set(InetMailboxArray *self, size_t pos, const InetMailbox *elem);
extern int InetMailboxArray_setWithoutCopy(InetMailboxArray *self, size_t pos, InetMailbox *elem);
extern int InetMailboxArray_append(InetMailboxArray *self, const InetMailbox *elem);
extern int InetMailboxArray_appendWithoutCopy(InetMailboxArray *self, InetMailbox *elem);
extern InetMailboxArray *InetMailboxArray_build2822MailboxList(const char *head, const char *tail,
                                                               const char **nextp,
                                                               const char **errptr);

#define InetMailboxArray_free(_self) PtrArray_free(_self)
#define InetMailboxArray_reset(_self) PtrArray_reset(_self)
#define InetMailboxArray_unappend(_self) PtrArray_unappend(_self)
#define InetMailboxArray_getCount(_self) PtrArray_getCount(_self)
#define InetMailboxArray_adjustSize(_self) PtrArray_adjustSize(_self)
#define InetMailboxArray_reserve(_self, _size) PtrArray_reserve(_self, _size)
#define InetMailboxArray_get(_self, _pos) ((const InetMailbox *) PtrArray_get(_self, _pos))
#define InetMailboxArray_steal(_self, _pos)  ((InetMailbox *) PtrArray_steal(_self, _pos))

#ifdef __cplusplus
}
#endif

#endif /* __INET_MAILBOX_H__ */
