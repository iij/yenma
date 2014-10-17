/*
 * Copyright (c) 2014 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifndef __IPADDR_BLOCK_TREE_H__
#define __IPADDR_BLOCK_TREE_H__

#include <sys/socket.h>
#include <stdbool.h>
#include <netinet/in.h>

typedef struct IpAddrBlockTree IpAddrBlockTree;

extern IpAddrBlockTree *IpAddrBlockTree_new(void (*userdata_destructor) (void *));
extern void IpAddrBlockTree_free(IpAddrBlockTree *self);
extern bool IpAddrBlockTree_insert4(IpAddrBlockTree *self, const struct in_addr *start4,
                                    const struct in_addr *end4, void *data);
extern bool IpAddrBlockTree_insert6(IpAddrBlockTree *self, const struct in6_addr *start6,
                                    const struct in6_addr *end6, void *data);
extern bool IpAddrBlockTree_insertBySockAddr(IpAddrBlockTree *self, const struct sockaddr *sstart,
                                             const struct sockaddr *send, void *data);
extern void *IpAddrBlockTree_lookup4(IpAddrBlockTree *self, const struct in_addr *addr4);
extern void *IpAddrBlockTree_lookup6(IpAddrBlockTree *self, const struct in6_addr *addr6);
extern void *IpAddrBlockTree_lookupBySockAddr(IpAddrBlockTree *self, const struct sockaddr *saddr);
extern bool IpAddrBlockTree_delete4(IpAddrBlockTree *self, const struct in_addr *start4,
                                    const struct in_addr *end4);
extern bool IpAddrBlockTree_delete6(IpAddrBlockTree *self, const struct in6_addr *start6,
                                    const struct in6_addr *end6);
extern bool IpAddrBlockTree_deleteBySockAddr(IpAddrBlockTree *self, const struct sockaddr *sstart,
                                             const struct sockaddr *send);

#endif /* __IPADDR_BLOCK_TREE_H__ */
