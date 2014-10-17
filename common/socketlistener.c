/*
 * Copyright (c) 2008-2014 Internet Initiative Japan Inc. All rights reserved.
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
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>

#include "ptrop.h"
#include "stdaux.h"
#include "socketlistener.h"

#ifndef SUN_LEN
/// sockaddr_un 構造体の実際のサイズを返すマクロ
#define SUN_LEN(su) \
        (sizeof(*(su)) - sizeof((su)->sun_path) + strlen((su)->sun_path))
#endif

static int
SocketListener_listenImpl(int family, int socktype, int protocol, const struct sockaddr *addr,
                          socklen_t addrlen, int backlog, int *fd)
{
    int listenfd = socket(family, socktype, protocol);
    if (0 > listenfd) {
        return EAI_SYSTEM;
    }   // end if

    static const int on = 1;
    if (0 != setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, (socklen_t) sizeof(on))) {
        goto cleanup;
    }   // end if

    if (0 != bind(listenfd, addr, addrlen)) {
        goto cleanup;
    }   // end if

    if (0 != listen(listenfd, backlog)) {
        goto cleanup;
    }   // end if

    *fd = listenfd;
    return 0;

  cleanup:;
    int save_errno = errno;
    SKIP_EINTR(close(listenfd));
    errno = save_errno;
    return EAI_SYSTEM;
}   // end function: SocketListener_listenImpl

/**
 * TCP ソケットを開く
 * @param host listen するソケットの IP アドレス/ホスト名
 * @param serv listen するソケットのポート番号/サービス名
 * @param ai_family listen するソケットのアドレスファミリ
 * @param addrlenp ソケットを開けた場合に，そのソケットで使用する
 *                 構造体のサイズを受け取る変数へのポインタ
 * @param backlog listen(2) に渡す backlog の値
 * @return 成功した場合は descriptor，失敗した場合は -1
 */
static int
SocketListener_listenInetImpl(int family, const char *host, const char *service, int backlog,
                              int *fd)
{
    assert(AF_INET != family || AF_INET6 != family || AF_UNSPEC != family);

    // getaddrinfo のヒントを準備する.
    struct addrinfo hints;
    memset(&hints, '\0', sizeof(struct addrinfo));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = family;
    hints.ai_flags = AI_PASSIVE;

    // DNSを引く. 遺憾ながらタイムアウト無し.
    struct addrinfo *addrinfo;
    int gai_error = getaddrinfo(host, service, &hints, &addrinfo);
    if (gai_error != 0) {
        return gai_error;
    }   // end if

    // XXX glibc の getaddrinfo() は RFC3484 に対応するため結果をソートしており,
    //     DNS ラウンドロビンしても結果が偏る.
    //     ただし distro によってはこの変更を取り込んでいない
    int first_gaierror = 0;
    struct addrinfo *ai = addrinfo;
    do {
        int gai_stat = SocketListener_listenImpl(ai->ai_family, ai->ai_socktype, ai->ai_protocol,
                                                 ai->ai_addr, ai->ai_addrlen, backlog, fd);
        if (0 == gai_stat) {
            freeaddrinfo(addrinfo);
            return 0;
        }   // end if

        // 最初に遭遇したエラーを保存しておく
        if (0 == first_gaierror) {
            first_gaierror = gai_stat;
        }   // end if
    } while (NULL != (ai = ai->ai_next));

    // getaddrinfo() が返してきた全てのアドレスで listen できなかった
    freeaddrinfo(addrinfo);
    return first_gaierror;
}   // end function: SocketListener_listenInetImpl

/**
 * TCP ソケットを開く
 * @param sock_string listen するソケットを表す文字列 (タグなし)
 * @param ai_family listen するソケットのアドレスファミリ
 * @param addrlenp ソケットを開けた場合に，そのソケットで使用する
 *                 構造体のサイズを受け取る変数へのポインタ
 * @param backlog listen(2) に渡す backlog の値
 * @return 成功した場合は descriptor，失敗した場合は -1
 */
static int
SocketListener_dispatchInetListener(int family, const char *sock_string, int backlog, int *fd)
{
    char *socknamebuf = strdup(sock_string);
    if (NULL == socknamebuf) {
        return EAI_MEMORY;
    }   // end if
    char *hostbase = strchr(socknamebuf, '@');
    if (NULL != hostbase) {
        *hostbase = '\0';
        hostbase++;
    }   // end if
    int ret = SocketListener_listenInetImpl(family, hostbase, socknamebuf, backlog, fd);
    free(socknamebuf);
    return ret;
}   // end function: SocketListener_dispatchInetListener

int
SocketListener_listenInet(const char *host, const char *service, int backlog, int *fd)
{
    return SocketListener_listenInetImpl(AF_UNSPEC, host, service, backlog, fd);
}   // end function: SocketListener_listenInet

int
SocketListener_listenInet4(const char *host, const char *service, int backlog, int *fd)
{
    return SocketListener_listenInetImpl(AF_INET, host, service, backlog, fd);
}   // end function: SocketListener_listenInet4

int
SocketListener_listenInet6(const char *host, const char *service, int backlog, int *fd)
{
    return SocketListener_listenInetImpl(AF_INET6, host, service, backlog, fd);
}   // end function: SocketListener_listenInet6

/**
 * ストリームタイプの UNIX ドメインソケットを開く
 * @param path listen する UNIX ドメインソケットへの path
 * @param addrlenp ソケットを開けた場合に，そのソケットで使用する
 *                 構造体のサイズを受け取る変数へのポインタ
 * @param backlog listen(2) に渡す backlog の値
 * @return 成功した場合は descriptor，失敗した場合は -1
 */
int
SocketListener_listenUnix(const char *sockpath, int backlog, int *fd)
{
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sockpath);
    return SocketListener_listenImpl(AF_UNIX, SOCK_STREAM, 0, (struct sockaddr *) &addr,
                                     SUN_LEN(&addr), backlog, fd);
}   // end function: SocketListener_listenUnix

/**
 * ストリームタイプのソケットを開く
 * @param sock_string listen するソケットを表す文字列
 * @param addrlenp ソケットを開けた場合に，そのソケットで使用する
 *                 構造体のサイズを受け取る変数へのポインタ
 * @param backlog listen(2) に渡す backlog の値
 * @return 成功した場合は descriptor，失敗した場合は -1
 * @note ソケットの表記方法については @ref sock_string を参照
 */
int
SocketListener_listen(const char *sockaddr, int backlog, int *fd)
{
    if (0 == strncasecmp(sockaddr, "inet:", 5)) {
        return SocketListener_dispatchInetListener(AF_INET, sockaddr + 5, backlog, fd);
    } else if (0 == strncasecmp(sockaddr, "inet6:", 6)) {
        return SocketListener_dispatchInetListener(AF_INET6, sockaddr + 6, backlog, fd);
    } else if (0 == strncasecmp(sockaddr, "unix:", 5)) {
        return SocketListener_listenUnix(sockaddr + 5, backlog, fd);
    } else if (0 == strncasecmp(sockaddr, "local:", 6)) {
        return SocketListener_listenUnix(sockaddr + 6, backlog, fd);
    } else {
        return SocketListener_dispatchInetListener(AF_UNSPEC, sockaddr, backlog, fd);
    }   // end if
}   // end function: SocketListener_listen

/**
 * @page sock_string ソケット指定文字列
 *
 * TCP ソケットの場合: [{@c address-family}:]{@c port-number}[\@{@c address}]
 * \li @c address-family: inet (IPv4), inet6 (IPv6), 無指定 (IPv4/IPv6 のうち有効な方) のいずれか
 * \li @c port-number: ポート番号
 * \li @c address: IP アドレス，ホスト名，無指定のいずれか．無指定の場合は INADDR_ANY/in6addr_any
 *
 * UNIX ドメインソケットの場合: {@c address-family}:{@c path-to-socket}
 * \li @c address-family: unix, local のいずれか (どちらでも同じ)
 * \li @c path-to-socket: ソケットへの絶対パス
 */
