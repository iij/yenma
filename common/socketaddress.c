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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <sys/socket.h>
#include <sys/un.h>
#include <stdbool.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>

#include "ptrop.h"
#include "socketaddress.h"

#if !defined(EAI_OVERFLOW)
// netdb.h of libbind does not have EAI_OVERFLOW
#define EAI_OVERFLOW EAI_FAIL
#endif

static int
SockAddr_getNumericAddrInfoImpl(int af, const char *ipaddr, struct sockaddr *saddr,
                                socklen_t *socklen)
{
    struct addrinfo hints, *addrinfo;
    memset(&hints, '\0', sizeof(struct addrinfo));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST;
    hints.ai_family = af;

    int gai_stat = getaddrinfo(ipaddr, NULL, &hints, &addrinfo);
    if (gai_stat != 0) {
        return gai_stat;
    }   // end if

    struct addrinfo *ai = addrinfo;
    do {
        if (AF_UNSPEC == af || ai->ai_family == af) {
            if (*socklen < ai->ai_addrlen) {
                freeaddrinfo(addrinfo);
                return EAI_OVERFLOW;
            }   // end if
            memcpy(saddr, ai->ai_addr, ai->ai_addrlen);
            *socklen = ai->ai_addrlen;
            freeaddrinfo(addrinfo);
            return 0;
        }   // end if
    } while (NULL != (ai = ai->ai_next));
    freeaddrinfo(addrinfo);
    return EAI_NONAME;
}   // end function: SockAddr_getNumericAddrInfoImpl

int
SockAddr_getNumericAddrInfo(const char *ipaddr, struct sockaddr *saddr, socklen_t *socklen)
{
    return SockAddr_getNumericAddrInfoImpl(AF_UNSPEC, ipaddr, saddr, socklen);
}   // end function: SockAddr_getNumericAddrInfo

int
SockAddr_parseIpAddrBlock(const char *entry, size_t entrylen, struct sockaddr *sstart,
                          socklen_t *sstartlen, struct sockaddr *send, socklen_t *sendlen)
{
    // guessing protocol
    int af;
    size_t addrlen;
    if (NULL != memchr(entry, ':', entrylen)) {
        af = AF_INET6;
        addrlen = 16;   // = 128 / 8
    } else {
        af = AF_INET;
        addrlen = 4;    // = 32 / 8
    }   // end if

    char entrybuf[INET6_ADDRSTRLEN * 2 + 2];    // enough size to store "111.222.333.444-555.666.777.888" format
    if ((int) sizeof(entrybuf) <=
        snprintf(entrybuf, sizeof(entrybuf), "%.*s", (int) entrylen, entry)) {
        return EAI_NONAME;  // invalid format
    }   // end if

    char *p;
    if (NULL != (p = strchr(entrybuf, '/'))) {
        // for "111.222.333.444/24" format
        *p = '\0';
        int ret = SockAddr_getNumericAddrInfoImpl(af, entrybuf, sstart, sstartlen);
        if (0 != ret) {
            return ret;
        }   // end if

        if (*sendlen < *sstartlen) {
            return EAI_OVERFLOW;
        }   // end if
        memcpy(send, sstart, *sstartlen);
        *sendlen = *sstartlen;

        ++p;
        unsigned long int mask = strtoul(p, NULL, 10);
        if (mask <= 0 || addrlen * 8 < mask) {
            return EAI_NONAME;
        }   // end if

        uint8_t bit_mask[addrlen];
        memset(bit_mask, 0, sizeof(bit_mask));
        ptrdiff_t offset;
        for (offset = 0; offset < (ptrdiff_t) (mask / 8); ++offset) {
            *(uint8_t *) ((void *) bit_mask + offset) = 0xff;
        }   // end for
        if (0 < mask % 8) {
            *(uint8_t *) ((void *) bit_mask + offset) =
                (~(uint8_t) 0) << ((uint8_t) 8 - (uint8_t) (mask % 8));
        }   // end if

        void *start = (af == AF_INET)
            ? ((void *) &(((struct sockaddr_in *) sstart)->sin_addr))
            : ((void *) &(((struct sockaddr_in6 *) sstart)->sin6_addr));
        void *end = (af == AF_INET)
            ? ((void *) &(((struct sockaddr_in *) send)->sin_addr))
            : ((void *) &(((struct sockaddr_in6 *) send)->sin6_addr));
        for (ptrdiff_t offset = 0; offset < (ptrdiff_t) addrlen; offset += sizeof(uint32_t)) {
            (*(uint32_t *) (start + offset)) &= (*(uint32_t *) ((void *) bit_mask + offset));
            (*(uint32_t *) (end + offset)) |= ~(*(uint32_t *) ((void *) bit_mask + offset));
        }   // end for
    } else if (NULL != (p = strchr(entrybuf, '-'))) {
        // for "111.222.333.444-555.666.777.888" format
        *p = '\0';
        int ret = SockAddr_getNumericAddrInfoImpl(af, entrybuf, sstart, sstartlen);
        if (0 != ret) {
            return ret;
        }   // end if
        ++p;
        ret = SockAddr_getNumericAddrInfoImpl(af, p, send, sendlen);
        if (0 != ret) {
            return ret;
        }   // end if
    } else {
        // simple "111.222.333.444" format
        int ret = SockAddr_getNumericAddrInfoImpl(af, entrybuf, sstart, sstartlen);
        if (0 != ret) {
            return ret;
        }   // end if

        if (*sendlen < *sstartlen) {
            return EAI_OVERFLOW;
        }   // end if
        memcpy(send, sstart, *sstartlen);
        *sendlen = *sstartlen;
    }   // end if

    return 0;
}   // end function: SockAddr_parseIpAddrBlock

static int
SockAddr_getNumericNameInfoImpl(const struct sockaddr *addr, socklen_t *socklen, bool with_port,
                                char *buf, size_t buflen)
{
    char peername[INET6_ADDRSTRLEN + 1];
    char peerserv[MAX_NUMERICSERV_LEN + 1];

    if (AF_INET == addr->sa_family || AF_INET6 == addr->sa_family) {
        int gai_stat = getnameinfo(addr, *socklen, peername, sizeof(peername),
                                   with_port ? peerserv : NULL, with_port ? sizeof(peerserv) : 0,
                                   NI_NUMERICHOST | NI_NUMERICSERV);
        if (0 != gai_stat) {
            return gai_stat;
        }   // end if
    }   // end if

    switch (addr->sa_family) {
    case AF_INET:
        if (with_port && 0 != ((struct sockaddr_in *) addr)->sin_port) {    // port が 0 の場合は port 番号を出力しない
            snprintf(buf, buflen, "%s:%s", peername, peerserv);
        } else {
            snprintf(buf, buflen, "%s", peername);
        }   // end if
        break;
    case AF_INET6:
        if (with_port && 0 != ((struct sockaddr_in6 *) addr)->sin6_port) {  // port が 0 の場合は port 番号を出力しない
            snprintf(buf, buflen, "[%s]:%s", peername, peerserv);
        } else {
            snprintf(buf, buflen, "%s", peername);
        }   // end if
        break;
    case AF_UNIX:
        snprintf(buf, buflen, "%s", ((struct sockaddr_un *) addr)->sun_path);
        break;
    default:
        return EAI_FAMILY;
    }   // end switch

    return 0;
}   // end function: SockAddr_getNumericNameInfoImpl

/**
 * sockaddr 構造体を人間に読みやすい文字列に変換する getnameinfo の wrapper.
 * AF_INET, AF_INET6, AF_UNIX のみサポート
 * @param 変換対象の sockaddr 構造体
 * @param socklen sockaddr 構造体の長さを格納する変数へのポインタ. 実行後は参照した sockaddr 構造体の長さを格納する.
 * @return 生成した文字列表現へのポインタ. エラーが発生した場合は NULL.
 * @attention 返値は使用後に free() で解放すること.
 */
int
SockAddr_getNumericNameInfo(const struct sockaddr *addr, socklen_t *socklen, bool with_port,
                            char *buf, size_t buflen)
{
    if (AF_INET6 == addr->sa_family
        && IN6_IS_ADDR_V4MAPPED(&((const struct sockaddr_in6 *) addr)->sin6_addr)) {
        // 'addr' is IPv4-mapped address
        struct sockaddr_in addr4;
        const struct sockaddr_in6 *paddr6 = (const struct sockaddr_in6 *) addr;
        addr4.sin_family = AF_INET;
        addr4.sin_port = paddr6->sin6_port;
        // IPv6 アドレスの下位 32bit を回収
        IN6_V4MAPPED_TO_INADDR(&paddr6->sin6_addr, &addr4.sin_addr);
        *socklen = sizeof(struct sockaddr_in);
        return SockAddr_getNumericNameInfoImpl((struct sockaddr *) &addr4, socklen, with_port, buf,
                                               buflen);
    } else {
        return SockAddr_getNumericNameInfoImpl(addr, socklen, with_port, buf, buflen);
    }   // end if
}   // end function: SockAddr_getNumericNameInfo

/**
 * in_addr, in6_addr 構造体を人間に読みやすい文字列に変換する getnameinfo の wrapper.
 * AF_INET, AF_INET6 のみサポート
 * @param sa_family アドレスファミリ. AF_INET と AF_INET6 のいずれか.
 * @param 変換対象の in_addr/in6_addr 構造体
 * @param dupaddr 参照した sockaddr 構造体のコピーを受け取る変数へのポインタ. 不要な場合は NULL.
 * @return 生成した文字列表現へのポインタ. エラーが発生した場合は NULL.
 * @attention 返値は使用後に free() で解放すること.
 */
int
SockAddr_getNumericNameInfoFromInetAddr(sa_family_t sa_family, const void *ipaddr, char *buf,
                                        size_t buflen)
{
    struct sockaddr_storage srcaddr;
    memset(&srcaddr, 0, sizeof(srcaddr));
    socklen_t socklen;
    srcaddr.ss_family = sa_family;
    switch (sa_family) {
    case AF_INET:
        memcpy(&((struct sockaddr_in *) &srcaddr)->sin_addr, ipaddr, sizeof(struct in_addr));
        socklen = sizeof(struct sockaddr_in);
        break;
    case AF_INET6:
        memcpy(&((struct sockaddr_in6 *) &srcaddr)->sin6_addr, ipaddr, sizeof(struct in6_addr));
        socklen = sizeof(struct sockaddr_in6);
        break;
    default:
        return EAI_FAMILY;
    }   // end switch
    return SockAddr_getNumericNameInfo((struct sockaddr *) &srcaddr, &socklen, false, buf, buflen);
}   // end function: SockAddr_getNameInfoFromInetAddr

/**
 * ソケットの対向アドレスを人間に読みやすい文字列で返す getpeername の wrapper.
 * AF_INET, AF_INET6, AF_UNIX のみサポート
 * @param fd 対象ソケットディスクリプタ
 * @param dupaddr 参照した sockaddr 構造体のコピーを受け取る変数へのポインタ. 不要な場合は NULL.
 * @return 生成した文字列表現へのポインタ. エラーが発生した場合は NULL.
 * @attention 返値は使用後に free() で解放すること.
 */
int
SockAddr_getNumericPeerName(int fd, bool with_port, char *buf, size_t buflen)
{
    struct sockaddr_storage peeraddr;
    socklen_t socklen = sizeof(peeraddr);
    if (0 != getpeername(fd, (struct sockaddr *) &peeraddr, &socklen)) {
        return EAI_SYSTEM;
    }   // end if
    return SockAddr_getNumericNameInfo((struct sockaddr *) &peeraddr, &socklen, with_port, buf,
                                       buflen);
}   // end function: SockAddr_getNumericPeerName
