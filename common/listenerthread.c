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

#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <netdb.h>

#include "ptrop.h"
#include "stdaux.h"
#include "loghandler.h"
#include "socketlistener.h"
#include "listenerthread.h"

struct ListenerThread {
    char *socket;
    pthread_t tid;
    pthread_mutex_t fdlock;
    volatile int listenfd;
    int (*handler) (void *context, int fd, const struct sockaddr *addr, socklen_t socklen);
    void *handler_arg;
};

static int
sock_unlink(int sockfd)
{
    struct sockaddr_storage ss;
    socklen_t sslen;

    sslen = sizeof(struct sockaddr_storage);
    if (0 > getsockname(sockfd, (struct sockaddr *) &ss, &sslen)) {
        return -1;
    }   // end if

    if (ss.ss_family == AF_UNIX) {
        struct sockaddr_un *psun = (struct sockaddr_un *) &ss;
        int unlink_stat;
        SKIP_EINTR(unlink_stat = unlink(psun->sun_path));
        if (0 > unlink_stat) {
            return -1;
        }   // end if
    }   // end if

    return 0;
}   // end function: sock_unlink

static int
sock_shutdown(int sockfd, int how)
{
    (void) sock_unlink(sockfd);
    return shutdown(sockfd, how);
}   // end function: sock_shutdown

static int
sock_close(int sockfd)
{
    (void) sock_unlink(sockfd);
    int close_stat;
    SKIP_EINTR(close_stat = close(sockfd));
    return close_stat;
}   // end function: sock_close

/*
 * ソケットを開いている場合に閉じる.
 */
void
ListenerThread_shutdown(ListenerThread *self)
{
    assert(NULL != self);

    // 複数のスレッドが同時に進入できるので厳密にはスレッドセーフではないが,
    // 仮に同時に進入しても後攻のスレッドが失敗するだけなので特にロックなどは使用しない
    // XXX
    pthread_mutex_lock(&(self->fdlock));
    int listenfd = self->listenfd;
    // XXX
    pthread_mutex_unlock(&(self->fdlock));
    if (0 <= listenfd) {
        self->listenfd = -1;    // 先にフィールドを潰す
        LogDebug("ListenerThread shutting down: listenfd=%d", listenfd);

        // 他のスレッドが accept() しているディスクリプタを閉じて accept() に割り込む
        int ret;
#if defined(__linux)
        ret = sock_shutdown(listenfd, SHUT_RDWR);   // listening socket を強制的に叩き落とす
        (void) sock_close(listenfd);
#elif defined(__sun)
        ret = sock_close(listenfd);
#else // Linux と Solaris 以外は試していない
#warning "shutdown process may block"
        ret = sock_close(listenfd);
#endif

        if (0 != ret) {
            LogError("socket shutdown failed: listenfd=%d, errno=%s", listenfd, strerror(errno));
        }   // end if
    }   // end if

    return;
}   // end function: ListenerThread_shutdown

/*
 * リソースを解放する.
 * ソケットがまだ開いている場合は閉じ, スレッドを回収する.
 * @attention 他のスレッドからアクセスされない状態で実行する必要がある.
 */
void
ListenerThread_free(ListenerThread *self)
{
    if (NULL == self) {
        return;
    }   // end if

    ListenerThread_shutdown(self);

    int ret = pthread_join(self->tid, NULL);
    if (ret) {
        LogError("pthread_join failed: tid=%u, errno=%s", (unsigned int) self->tid, strerror(ret));
    }   // end if

    (void) pthread_mutex_destroy(&(self->fdlock));
    free(self->socket);
    free(self);
    return;
}   // end function: ListenerThread_free

static void *
ListenerThread_main(void *arg)
{
    ListenerThread *self = (ListenerThread *) arg;

    LogDebug("socket listener thread spawned: tid=%u, listenfd=%d", (unsigned int) self->tid,
             self->listenfd);

    while (true) {
        // XXX
        pthread_mutex_lock(&(self->fdlock));
        int listenfd = self->listenfd;
        // XXX
        pthread_mutex_unlock(&(self->fdlock));
        if (listenfd < 0) {
            break;
        }   // end if
        // このタイミングで listenfd が無効になる可能性が残るが,
        // 万が一, accept しても EBADF が返るだけなので特に気にしない. (?)
        struct sockaddr_storage addr;
        socklen_t addrlen = sizeof(struct sockaddr_storage);
        int connfd = accept(listenfd, (struct sockaddr *) &addr, &addrlen);
        if (connfd < 0) {
            if (errno == EINTR  // signal による割り込み
                || errno == ECONNABORTED) { // accept が完了しないうちに相手が切断
                LogNotice("accept interrupted: listenfd=%d, errno=%s", listenfd, strerror(errno));
            } else if (errno == EBADF || errno == ENOTSOCK || errno == EINVAL) {
                // close(2)/shutdown(2) で強引に割り込んだ.
                // listenfd のチェックをしてから accept がよばれるまでに listenfd が入れ替わった.
                LogNotice("accept interrupted: listenfd=%d, errno=%s", listenfd, strerror(errno));
            } else {    // その他のエラー
                LogError("accept failed: listenfd=%d, errno=%s", listenfd, strerror(errno));
            }   // end if
            continue;
        }   // end if
        LogDebug("ListenerThread accepting: connfd=%d", connfd);

        // ハンドラをコールバック
        int ret = (self->handler) (self->handler_arg, connfd, (struct sockaddr *) &addr, addrlen);
        SKIP_EINTR(close(connfd));
        connfd = -1;

        if (0 != ret) {
            LogDebug("ListenerThread closing by callback handelr: ret=%d", ret);
            break;
        }   // end if
    }   // end for
    LogDebug("socket listener thread shutting down: tid=%u, listenfd=%d", (unsigned int) self->tid,
             self->listenfd);
    ListenerThread_shutdown(self);

    return NULL;
}   // end function: ListenerThread_main

/*
 * pthread_create() するので fork() の後の方が安心.
 */
ListenerThread *
ListenerThread_create(const char *control_socket, int backlog,
                      int (*handler) (void *, int, const struct sockaddr *, socklen_t),
                      void *handler_arg)
{
    assert(NULL != control_socket);

    ListenerThread *self = (ListenerThread *) malloc(sizeof(ListenerThread));
    if (NULL == self) {
        return NULL;
    }   // end if
    memset(self, 0, sizeof(ListenerThread));

    self->listenfd = -1;
    self->handler = handler;
    self->handler_arg = handler_arg;
    self->socket = NULL;

    // XXX
    pthread_mutex_init(&(self->fdlock), NULL);

    int listenfd = -1;
    int listen_stat = SocketListener_listen(control_socket, backlog, &listenfd);
    if (0 != listen_stat) {
        int save_errno = errno;
        LogWarning("failed to format the source ip address: error=%s",
                   (EAI_SYSTEM != listen_stat) ? gai_strerror(listen_stat) : strerror(save_errno));
        goto cleanup;
    }   // end if
    self->listenfd = listenfd;

    self->socket = strdup(control_socket);
    if (NULL == self->socket) {
        LogNoResource();
        goto cleanup;
    }   // end if

    // 生成するスレッドがシグナルを受けないようにする
    sigset_t blockmask, oldmask;
    sigfillset(&blockmask);
    int sigstat = pthread_sigmask(SIG_SETMASK, &blockmask, &oldmask);
    if (0 != sigstat) {
        LogWarning("pthread_sigmask failed: errno=%s", strerror(sigstat));
    }   // end if

    // スレッドの生成
    int threadstat = pthread_create(&(self->tid), NULL, ListenerThread_main, (void *) self);

    // シグナルマスクを戻す
    sigstat = pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
    if (0 != sigstat) {
        LogWarning("pthread_sigmask failed: errno=%s", strerror(sigstat));
    }   // end if

    if (0 != threadstat) {
        LogError("pthread_create failed: errno=%s", strerror(threadstat));
        goto cleanup;
    }   // end if

    return self;

  cleanup:
    if (0 <= self->listenfd) {
        sock_close(self->listenfd);
    }   // end if
    free(self->socket);
    free(self);
    return NULL;
}   // end function: ListenerThread_create
