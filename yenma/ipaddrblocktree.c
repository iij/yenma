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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <sys/socket.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include "rbtree.h"
#include "ipaddrblocktree.h"

#if !defined(IN6_INADDR_TO_V4MAPPED)
/*
 * substitute for IN6_INADDR_TO_V4MAPPED on Solaris
 * IPv4-mapped IPv6 address
 * |                80 bits               | 16 |      32 bits        |
 * |0000..............................0000|FFFF|    IPV4 ADDRESS     |
 */
#define IN6_INADDR_TO_V4MAPPED(_v4, _v6) \
    do { \
        memset((void *)(_v6), 0, 10); \
        memset((void *)(_v6) + 10, 0xff, 2); \
        memcpy((void *)(_v6) + 12, (void *)(_v4), sizeof(in_addr_t)); \
    } while (0)
#endif

typedef struct IpAddrBlockTreeNode {
    rbnode_t rbnode;
    struct in6_addr start;
    struct in6_addr end;
    void (*userdata_destructor) (void *);
    void *userdata;
} IpAddrBlockTreeNode;

struct IpAddrBlockTree {
    rbtree_t tree;
    void (*userdata_destructor) (void *);
};

static int
IpAddrBlockTreeNode_compare(const void *node0, const void *node1)
{
    const IpAddrBlockTreeNode *ipnode0 = (const IpAddrBlockTreeNode *) node0;
    const IpAddrBlockTreeNode *ipnode1 = (const IpAddrBlockTreeNode *) node1;

    if (0 > memcmp(&ipnode0->end, &ipnode1->start, sizeof(struct in6_addr))) {
        return -1;
    } else if (0 > memcmp(&ipnode1->end, &ipnode0->start, sizeof(struct in6_addr))) {
        return 1;
    } else {
        return 0;
    }   // end if
}   // end function: IpAddrBlockTreeNode_compare

static void
IpAddrBlockTreeNode_free(IpAddrBlockTreeNode *self)
{
    if (NULL == self) {
        return;
    }   // end if

    if (NULL != self->userdata_destructor) {
        self->userdata_destructor((void *) self->userdata);
    }   // end if
    free(self);
}   // end function: IpAddrBlockTreeNode_free

static bool
IpAddrBlockTree_insertImpl(IpAddrBlockTree *self, IpAddrBlockTreeNode *node)
{
    node->rbnode.key = node;
    if (NULL == rbtree_insert(&self->tree, &node->rbnode)) {
        free(node);
        errno = EEXIST;
        return false;
    }   // end if
    return true;
}   // end function: IpAddrBlockTree_insertImpl

bool
IpAddrBlockTree_insert4(IpAddrBlockTree *self, const struct in_addr *start4,
                        const struct in_addr *end4, void *data)
{
    IpAddrBlockTreeNode *node = (IpAddrBlockTreeNode *) malloc(sizeof(IpAddrBlockTreeNode));
    if (NULL == node) {
        return false;
    }   // end if
    memset(node, 0, sizeof(IpAddrBlockTreeNode));

    if (0 >= memcmp(start4, end4, sizeof(struct in_addr))) {
        IN6_INADDR_TO_V4MAPPED(start4, &node->start);
        IN6_INADDR_TO_V4MAPPED(end4, &node->end);
    } else {
        IN6_INADDR_TO_V4MAPPED(end4, &node->start);
        IN6_INADDR_TO_V4MAPPED(start4, &node->end);
    }   // end if
    node->userdata = data;
    node->userdata_destructor = self->userdata_destructor;
    return IpAddrBlockTree_insertImpl(self, node);
}   // end function: IpAddrBlockTree_insert4

bool
IpAddrBlockTree_insert6(IpAddrBlockTree *self, const struct in6_addr *start6,
                        const struct in6_addr *end6, void *data)
{
    IpAddrBlockTreeNode *node = (IpAddrBlockTreeNode *) malloc(sizeof(IpAddrBlockTreeNode));
    if (NULL == node) {
        return false;
    }   // end if
    memset(node, 0, sizeof(IpAddrBlockTreeNode));

    if (0 >= memcmp(start6, end6, sizeof(struct in6_addr))) {
        memcpy(&node->start, start6, sizeof(struct in6_addr));
        memcpy(&node->end, end6, sizeof(struct in6_addr));
    } else {
        memcpy(&node->end, start6, sizeof(struct in6_addr));
        memcpy(&node->start, end6, sizeof(struct in6_addr));
    }   // end if
    node->userdata = data;
    node->userdata_destructor = self->userdata_destructor;
    return IpAddrBlockTree_insertImpl(self, node);
}   // end function: IpAddrBlockTree_insert6

bool
IpAddrBlockTree_insertBySockAddr(IpAddrBlockTree *self, const struct sockaddr *sstart,
                                 const struct sockaddr *send, void *data)
{
    assert(sstart->sa_family == send->sa_family);

    switch (sstart->sa_family) {
    case AF_INET:
        return IpAddrBlockTree_insert4(self, &((struct sockaddr_in *) sstart)->sin_addr,
                                       &((struct sockaddr_in *) send)->sin_addr, data);
    case AF_INET6:
        return IpAddrBlockTree_insert6(self, &((struct sockaddr_in6 *) sstart)->sin6_addr,
                                       &((struct sockaddr_in6 *) send)->sin6_addr, data);
    default:
        errno = EINVAL;
        return false;
    }   // end switch
}   // end function: IpAddrBlockTree_insertBySockAddr

static void *
IpAddrBlockTree_lookupImpl(IpAddrBlockTree *self, const IpAddrBlockTreeNode *needle)
{
    rbnode_t *found = rbtree_search(&self->tree, needle);
    if (NULL == found || NULL == found->key) {
        return NULL;
    }   // end if

    IpAddrBlockTreeNode *candidate = (IpAddrBlockTreeNode *) found->key;
    return (0 >= memcmp(&candidate->start, &needle->start, sizeof(struct in6_addr))
            && 0 <= memcmp(&candidate->end, &needle->end, sizeof(struct in6_addr)))
        ? candidate->userdata : NULL;
}   // end function: IpAddrBlockTree_lookupImpl

void *
IpAddrBlockTree_lookup4(IpAddrBlockTree *self, const struct in_addr *addr4)
{
    IpAddrBlockTreeNode needle;
    IN6_INADDR_TO_V4MAPPED(addr4, &needle.start);
    IN6_INADDR_TO_V4MAPPED(addr4, &needle.end);
    return IpAddrBlockTree_lookupImpl(self, &needle);
}   // end function: IpAddrBlockTree_lookup4

void *
IpAddrBlockTree_lookup6(IpAddrBlockTree *self, const struct in6_addr *addr6)
{
    IpAddrBlockTreeNode needle;
    memcpy(&needle.start, addr6, sizeof(struct in6_addr));
    memcpy(&needle.end, addr6, sizeof(struct in6_addr));
    return IpAddrBlockTree_lookupImpl(self, &needle);
}   // end function: IpAddrBlockTree_lookup6

void *
IpAddrBlockTree_lookupBySockAddr(IpAddrBlockTree *self, const struct sockaddr *saddr)
{
    switch (saddr->sa_family) {
    case AF_INET:
        return IpAddrBlockTree_lookup4(self, &((struct sockaddr_in *) saddr)->sin_addr);
    case AF_INET6:
        return IpAddrBlockTree_lookup6(self, &((struct sockaddr_in6 *) saddr)->sin6_addr);
    default:
        return NULL;
    }   // end switch
}   // end function: IpAddrBlockTree_lookupBySockAddr

static IpAddrBlockTreeNode *
IpAddrBlockTree_getExactMatchNode(IpAddrBlockTree *self, const IpAddrBlockTreeNode *needle)
{
    rbnode_t *found = rbtree_search(&self->tree, needle);
    if (NULL == found || NULL == found->key) {
        return NULL;
    }   // end if

    IpAddrBlockTreeNode *candidate = (IpAddrBlockTreeNode *) found->key;
    return (0 == memcmp(&candidate->start, &needle->start, sizeof(struct in6_addr))
            && 0 == memcmp(&candidate->end, &needle->end, sizeof(struct in6_addr)))
        ? candidate : NULL;
}   // end function: IpAddrBlockTree_getExactMatchNode

static bool
IpAddrBlockTree_deleteImpl(IpAddrBlockTree *self, const IpAddrBlockTreeNode *needle)
{
    IpAddrBlockTreeNode *candidate = IpAddrBlockTree_getExactMatchNode(self, needle);
    if (NULL == candidate) {
        return false;
    }   // end if
    rbnode_t *deleted_rbnode = rbtree_delete(&self->tree, needle);
    if (NULL == deleted_rbnode) {
        // must not reach here
        return false;
    }   // end if
    IpAddrBlockTreeNode_free((IpAddrBlockTreeNode *) deleted_rbnode->key);
    return true;
}   // end function: IpAddrBlockTree_deleteImpl

bool
IpAddrBlockTree_delete4(IpAddrBlockTree *self, const struct in_addr *start4,
                        const struct in_addr *end4)
{
    IpAddrBlockTreeNode needle;
    if (0 >= memcmp(start4, end4, sizeof(struct in_addr))) {
        IN6_INADDR_TO_V4MAPPED(start4, &needle.start);
        IN6_INADDR_TO_V4MAPPED(end4, &needle.end);
    } else {
        IN6_INADDR_TO_V4MAPPED(end4, &needle.start);
        IN6_INADDR_TO_V4MAPPED(start4, &needle.end);
    }   // end if
    return IpAddrBlockTree_deleteImpl(self, &needle);
}   // end function: IpAddrBlockTree_delete4

bool
IpAddrBlockTree_delete6(IpAddrBlockTree *self, const struct in6_addr *start6,
                        const struct in6_addr *end6)
{
    IpAddrBlockTreeNode needle;
    if (0 >= memcmp(start6, end6, sizeof(struct in6_addr))) {
        memcpy(&needle.start, start6, sizeof(struct in6_addr));
        memcpy(&needle.end, end6, sizeof(struct in6_addr));
    } else {
        memcpy(&needle.end, start6, sizeof(struct in6_addr));
        memcpy(&needle.start, end6, sizeof(struct in6_addr));
    }   // end if
    return IpAddrBlockTree_deleteImpl(self, &needle);
}   // end function: IpAddrBlockTree_delete6

bool
IpAddrBlockTree_deleteBySockAddr(IpAddrBlockTree *self, const struct sockaddr *sstart,
                                 const struct sockaddr *send)
{
    assert(sstart->sa_family == send->sa_family);

    switch (sstart->sa_family) {
    case AF_INET:
        return IpAddrBlockTree_delete4(self, &((struct sockaddr_in *) sstart)->sin_addr,
                                       &((struct sockaddr_in *) send)->sin_addr);
    case AF_INET6:
        return IpAddrBlockTree_delete6(self, &((struct sockaddr_in6 *) sstart)->sin6_addr,
                                       &((struct sockaddr_in6 *) send)->sin6_addr);
    default:
        return false;
    }   // end switch
}   // end function: IpAddrBlockTree_deleteBySockAddr

static void
IpAddrBlockTree_freeNode(rbnode_t *rbnode, void *arg __attribute__((unused)))
{
    if (NULL == rbnode || RBTREE_NULL == rbnode) {
        return;
    }   // end if

    IpAddrBlockTreeNode_free((IpAddrBlockTreeNode *) rbnode->key);
}   // end function: IpAddrBlockTree_freeNode

void
IpAddrBlockTree_free(IpAddrBlockTree *self)
{
    if (NULL == self) {
        return;
    }   // end if

    traverse_postorder(&self->tree, IpAddrBlockTree_freeNode, self);
    free(self);
}   // end function: IpAddrBlockTree_free

IpAddrBlockTree *
IpAddrBlockTree_new(void (*userdata_destructor) (void *))
{
    IpAddrBlockTree *self = (IpAddrBlockTree *) malloc(sizeof(IpAddrBlockTree));
    if (NULL == self) {
        return NULL;
    }   // end if
    memset(self, 0, sizeof(IpAddrBlockTree));
    rbtree_init(&self->tree, IpAddrBlockTreeNode_compare);
    self->userdata_destructor = userdata_destructor;
    return self;
}   // end function: IpAddrBlockTree_new
