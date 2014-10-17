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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <pwd.h>
#include <sysexits.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <assert.h>
#include <sys/resource.h>

#ifdef HAVE_SYS_PRCTL_H
# include <sys/prctl.h>
#endif

#include "stdaux.h"
#include "ptrop.h"
#include "daemon_stuff.h"

/// テンポラリバッファのサイズ
#define PIDNUMBUF 128

#define PATH_DEVNULL "/dev/null"

struct PidFile {
    bool with_lock;
    int fd;
    char *path;
};

/*
 * @attention Record locks are not inherited by a child created via fork(2), but
 *            are preserved across an execve(2).
 */
PidFile *
PidFile_create(const char *path, bool with_lock, const char **errstr)
{
    assert(NULL != path);

    PidFile *pidfile = (PidFile *) malloc(sizeof(PidFile));
    if (NULL == pidfile) {
        SETDEREF(errstr, "memory allocation failed");
        return NULL;
    }   // end if
    memset(pidfile, 0, sizeof(PidFile));
    pidfile->fd = -1;
    pidfile->with_lock = false;

    pidfile->path = strdup(path);
    if (NULL == pidfile->path) {
        SETDEREF(errstr, "memory allocation failed");
        goto cleanup;
    }   // end if

    // fcntl() で排他ロックを取得するには書き込みモードでオープンしている必要がある
    SKIP_EINTR(pidfile->fd = open(path, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH));
    if (pidfile->fd < 0) {
        SETDEREF(errstr, "open failed");
        goto cleanup;
    }   // end if

    if (with_lock) {
        // acquiring advisory lock
        struct flock advlock;
        advlock.l_type = F_WRLCK;
        advlock.l_start = 0;
        advlock.l_whence = SEEK_SET;
        advlock.l_len = 0;

        if (0 > fcntl(pidfile->fd, F_SETLK, &advlock)) {
            if (EAGAIN == errno || EACCES == errno) {
                SETDEREF(errstr, "pidfile exclusively locked");
            } else {
                SETDEREF(errstr, "fcntl failed");
            }   // end if
            goto cleanup;
        }   // end if
        pidfile->with_lock = with_lock;
    }   // end if

    int trunc_stat;
    SKIP_EINTR(trunc_stat = ftruncate(pidfile->fd, 0));
    if (0 > trunc_stat) {
        SETDEREF(errstr, "ftruncate failed");
        goto cleanup;
    }   // end if

    char buf[PIDNUMBUF];
    snprintf(buf, PIDNUMBUF, "%d", (int) getpid());
    ssize_t writelen;
    SKIP_EINTR(writelen = write(pidfile->fd, buf, strlen(buf)));
    if (0 > writelen) {
        SETDEREF(errstr, "write failed");
        goto cleanup;
    }   // end if

    SETDEREF(errstr, NULL);
    return pidfile;

  cleanup:;
    int save_error = errno;
    PidFile_close(pidfile, true);
    errno = save_error;
    return NULL;
}   // end function: PidFile_create

/*
 * 指定した pidfile が存在するか. 存在する場合はロックされているかを調べる.
 * @return true on success, false on failure.
 */
bool
PidFile_isLocked(const char *path, const char **errstr)
{
    bool is_locked = false;

    // 書き込みモードでオープンし, 排他ロックの取得を試みる
    int fd;
    SKIP_EINTR(fd = open(path, O_WRONLY /* O_RDONLY */ ));
    if (0 > fd) {
        if (ENOENT == errno) {
            // pidfile が存在しない
            SETDEREF(errstr, NULL);
            return false;
        } else {
            SETDEREF(errstr, "open failed");
            return false;
        }   // end if
    }   // end if

    // acquiring advisory lock
    struct flock advlock;
    advlock.l_type = F_WRLCK;
    advlock.l_start = 0;
    advlock.l_whence = SEEK_SET;
    advlock.l_len = 0;
    if (0 == fcntl(fd, F_GETLK, &advlock)) {
        if (F_UNLCK != advlock.l_type)
            is_locked = true;
        SETDEREF(errstr, NULL);
    } else {
        SETDEREF(errstr, "fcntl failed");
    }   // end if

    int saverrno = errno;
    SKIP_EINTR(close(fd));
    errno = saverrno;

    return is_locked;
}   // end function: PidFile_isLocked

void
PidFile_close(PidFile *pidfile, bool with_unlink)
{
    assert(NULL != pidfile);

    if (NULL != pidfile->path) {
        if (0 <= pidfile->fd) {
            if (with_unlink)
                (void) unlink(pidfile->path);
            // ロックは close(2) と共に消える
            SKIP_EINTR(close(pidfile->fd));
        }   // end if
        free(pidfile->path);
    }   // end if

    free(pidfile);
    return;
}   // end function: PidFile_close

/**
 * /dev/null を open() して STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO に dup2() する.
 * 主に tty を解放するために用いる.
 * @return 成功した場合は 0, 失敗した場合は -1
 */
int
close_tty(void)
{
    int fd;
    SKIP_EINTR(fd = open(PATH_DEVNULL, O_RDWR));
    if (fd < 0) {
        return -1;
    }   // end if
    SKIP_EINTR(dup2(fd, STDIN_FILENO));
    SKIP_EINTR(dup2(fd, STDOUT_FILENO));
    SKIP_EINTR(dup2(fd, STDERR_FILENO));
    if (fd > 2) {
        SKIP_EINTR(close(fd));
    }   // end if
    return 0;
}   // end function: close_tty

static int
setuidgid_r(const char *username, const char **errstr, bool effective)
{
    int ret;
    struct passwd pwd, *ppwd;

    long buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (0 > buflen) {
        SETDEREF(errstr, "sysconf failed");
        return -1;
    }   // end if
    char *buf = (char *) malloc(buflen);
    if (NULL == buf) {
        SETDEREF(errstr, "memory allocation failed");
        return -1;
    }   // end if

    // XXX EINTR
    while (0 != (ret = getpwnam_r(username, &pwd, buf, buflen, &ppwd)) && ret == ERANGE) {
        // sysconf() は本来十分なサイズを返すべきなのだが, 稀に十分でない場合がある (らしい)
        buflen *= 2;
        char *newbuf = (char *) realloc(buf, buflen);
        if (NULL == newbuf) {
            SETDEREF(errstr, "memory allocation failed");
            free(buf);
            return -1;
        }   // end if
        buf = newbuf;
    }   // end while

    if (0 != ret || NULL == ppwd) {
        SETDEREF(errstr, "invalid username specified");
        free(buf);
        return -1;
    }   // end if

    // setgid/setegid
    ret = effective ? setegid(pwd.pw_gid) : setgid(pwd.pw_gid);
    if (0 > ret) {
        SETDEREF(errstr, "setgid failed");
        free(buf);
        return -1;
    }   // end if

    // setuid/seteuid
    ret = effective ? seteuid(pwd.pw_uid) : setuid(pwd.pw_uid);
    if (0 > ret) {
        SETDEREF(errstr, "setuid failed");
        free(buf);
        return -1;
    }   // end if

    free(buf);
    errstr = NULL;

    return 0;
}   // end function: setuidgid_r

/**
 * username で指定したユーザーが所属するグループに setgid() し,
 * username で指定したユーザーに setuid() する.
 * @param username 変更する uid と gid をひくためのユーザー名
 * @param errstr エラー発生時にエラーメッセージを受け取るポインタ
 * @return 成功した場合は 0，失敗した場合は -1
 * @attention setuid()/setgid() するのに十分な権限 (通常はスーパーユーザー) を想定している
 * @attention setgid() に成功し, setuid() に失敗しても gid は rollback されない
 */
int
setuidgid(const char *username, const char **errstr)
{
    return setuidgid_r(username, errstr, false);
}   // end function: setuidgid

/**
 * username で指定したユーザーが所属するグループに setegid() し,
 * username で指定したユーザーに seteuid() する.
 * @param username 変更する uid と gid をひくためのユーザー名
 * @param errstr エラー発生時にエラーメッセージを受け取るポインタ
 * @return 成功した場合は 0，失敗した場合は -1
 * @attention seteuid()/setegid() するのに十分な権限 (通常はスーパーユーザー) を想定している
 * @attention setegid() に成功し, seteuid() に失敗しても gid は rollback されない
 */
int
seteuidgid(const char *username, const char **errstr)
{
    return setuidgid_r(username, errstr, true);
}   // end function: seteuidgid

/**
 * プロセスを daemonize する
 * @param user NULL でない場合, 指定したユーザーが所属するグループに setegid() し,
 *             指定したユーザーに seteuid() する.
 * @param rootdir NULL でない場合, 指定されたディレクトリに chdir する.
 * @param errstr エラー発生時にエラーメッセージを受け取るポインタ
 * @return 成功した場合は 0, 失敗した場合は -1
 */
int
daemon_init(const char *user, const char *rootdir, const char **errstr)
{
    // core サイズの soft/hard limit を unlimited にする
    struct rlimit rlim;
    rlim.rlim_cur = RLIM_INFINITY;  // soft limit
    rlim.rlim_max = RLIM_INFINITY;  // hard limit
    if (-1 == setrlimit(RLIMIT_CORE, &rlim)) {
        SETDEREF(errstr, "setrlimit failed");
        return -1;
    }   // end if

    // setuid
    if (user) {
        if (0 > setuidgid(user, errstr)) {
            return -1;
        }   // end if

#ifdef HAVE_PRCTL
        // Linux でクラッシュ時に core を吐けるようにする
        if (0 != prctl(PR_SET_DUMPABLE, 1, 0, 0, 0)) {
            SETDEREF(errstr, "prctl failed");
            return -1;
        }   // end if
#endif
    }   // end if

    // 自分が既にプロセスグループリーダーである場合は setsid() が失敗するので, まず fork()
    pid_t pid = fork();
    if (0 != pid) {
        exit(EX_OK);    // parent terminates
    }   // end if
    // この時点で子プロセス側はプロセスグループリーダーではないことが保証される

    // セッションリーダーであり, コントロールターミナルを持たない状態になる
    setsid();

    // セッションリーダーが終了する際, 全ての子プロセスに SIGHUP が送られるのでそれを無視する
    struct sigaction act, oact;
    act.sa_handler = SIG_IGN;
    sigemptyset(&act.sa_mask);
    sigaddset(&act.sa_mask, SIGHUP);
    act.sa_flags = 0;
    if (sigaction(SIGHUP, &act, &oact) < 0) {
        SETDEREF(errstr, "sigaction failed");
        return -1;
    }   // end if

    pid = fork();
    if (0 != pid) { // this generates SIGHUP
        exit(EX_OK);    // parent terminates
    }   // end if

    // この時点で子プロセス側はセッションリーダーでないことが保証される
    // 以後ターミナルデバイスを開いても, そのターミナルはコントロールターミナルにはならない

    if (0 > sigaction(SIGHUP, &oact, &act)) {   // recover signal mask
        SETDEREF(errstr, "sigaction failed");
        return -1;
    }   // end if

    if (rootdir) {
        SKIP_EINTR(chdir(rootdir)); // change working directory
    }   // end if
    umask(0);   // clear file mode creation mask

    errstr = NULL;
    return 0;
}   // end function: daemon_init
