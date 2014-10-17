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

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libmilter/mfapi.h>

#include "ptrop.h"
#include "xparse.h"
#include "milteraux.h"

#define LOCALADDR4  "127.0.0.1"

/**
 * milter に関する設定をまとめておこなう
 * @param timeout 0 以上の値が指定された場合のみ設定する
 * @param backlog 0 より大きい値が指定されて場合のみ設定する
 * @return 成功した場合は 0, 失敗した場合は -1
 * @note ソケットを開くので, 特権ポートを開く場合は root 権限が必要
 */
int
milter_setup(struct smfiDesc *descr, char *miltersock, int backlog, int timeout, int debuglevel,
             const char **errstr)
{
    if (MI_FAILURE == smfi_setconn(miltersock)) {   // milter socket の設定
        SETDEREF(errstr, "smfi_setconn failed");
        return -1;
    }   // end if

    // この辺の関数は変数を設定するだけなので失敗しない
    smfi_setdbg(debuglevel);
    if (timeout >= 0) {
        smfi_settimeout(timeout);
    }   // end if

    if (backlog > 0) {
        smfi_setbacklog(backlog);
    }   // end if

    if (MI_FAILURE == smfi_register(*descr)) {
        SETDEREF(errstr, "smfi_register failed");
        return -1;
    }   // end if

    // smfi_register, smfi_setbacklog, smfi_setconn の後
    if (MI_FAILURE == smfi_opensocket(0)) {
        SETDEREF(errstr, "smfi_opensocket failed");
        return -1;
    }   // end if

    SETDEREF(errstr, NULL);
    return 0;
}   // end function: milter_setup

/**
 * milter の connect コールバック関数で渡されるソケットアドレス構造体を複製する.
 * sendmail がパイプ経由でデータを受け取った場合など,
 * 引数が NULL の場合は 127.0.0.1 を示すアドレス構造体を生成する.
 * @param hostaddr 複製したいソケットアドレス構造体へのポインタ.
 * @return 複製もしくは生成されたソケットアドレス構造体へのポインタ.
 *         使用後は free() によって解放する必要がある.
 *         メモリを確保できなかった場合は NULL.
 */
_SOCK_ADDR *
milter_dupaddr(const _SOCK_ADDR *hostaddr)
{
    socklen_t address_len = 0;
    if (NULL != hostaddr) {
        switch (hostaddr->sa_family) {
        case AF_INET:
            address_len = sizeof(struct sockaddr_in);
            break;
        case AF_INET6:
            address_len = sizeof(struct sockaddr_in6);
            break;
        case AF_UNIX:
            address_len = sizeof(struct sockaddr_un);
            break;
        default:
            // 未対応のアドレスファミリに対しては 127.0.0.1 を返す
            break;
        }   // end switch
    }   // end if

    if (0 < address_len) {
        _SOCK_ADDR *psock = (_SOCK_ADDR *) malloc(address_len);
        if (NULL == psock) {
            return NULL;
        }   // end if
        memcpy(psock, hostaddr, address_len);
        return psock;
    } else {
        // 127.0.0.1 を示すソケットアドレス構造体を生成する.
        struct sockaddr_in *psock = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
        if (NULL == psock) {
            return NULL;
        }   // end if
        psock->sin_family = AF_INET;
        psock->sin_port = 0;
        if (1 != inet_pton(AF_INET, LOCALADDR4, &(psock->sin_addr))) {  // XXX INADDR_LOOPBACK 使う?
            free(psock);
            return NULL;
        }   // end if
        return (_SOCK_ADDR *) psock;
    }   // end if
}   // end function: milter_dupaddr
