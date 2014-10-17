/*
 * Copyright (c) 2012-2014 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifndef __SOCKET_ADDRESS_H__
#define __SOCKET_ADDRESS_H__

#include <sys/socket.h>
#include <sys/types.h>
#include <stdbool.h>
#include <netinet/in.h>

#define MAX_NUMERICSERV_LEN 5   // = strlen("65535")
#define MAX_NUMERICINFO_LEN (INET6_ADDRSTRLEN + MAX_NUMERICSERV_LEN + 3)    // "[%s]:%s" (does not include terminating null character)

#if !defined(IN6_V4MAPPED_TO_INADDR)
// substitute for IN6_V4MAPPED_TO_INADDR on Solaris
#define IN6_V4MAPPED_TO_INADDR(_v6, _v4) \
    memcpy((void *)(_v4), (void *)(_v6) + (sizeof(struct in6_addr) - sizeof(in_addr_t)), sizeof(in_addr_t))
#endif

extern int SockAddr_getNumericAddrInfo(const char *ipaddr, struct sockaddr *saddr,
                                       socklen_t *socklen);
extern int SockAddr_parseIpAddrBlock(const char *entry, size_t entrylen, struct sockaddr *sstart,
                                     socklen_t *sstartlen, struct sockaddr *send,
                                     socklen_t *sendlen);
extern int SockAddr_getNumericNameInfo(const struct sockaddr *addr, socklen_t *socklen,
                                       bool with_port, char *buf, size_t buflen);
extern int SockAddr_getNumericNameInfoFromInetAddr(sa_family_t sa_family, const void *ipaddr,
                                                   char *buf, size_t buflen);
extern int SockAddr_getNumericPeerName(int fd, bool with_port, char *buf, size_t buflen);

#endif // __SOCKET_ADDRESS_H__
