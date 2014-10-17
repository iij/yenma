/*
 * Copyright (c) 2007-2010 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */
// timeval 構造体を操作するマクロ集, ほとんどが BSD 由来

#ifndef _TIMEOP_H_
#define _TIMEOP_H_

#ifndef timerclear
#define timerclear(tvp)         ((tvp)->tv_sec = (tvp)->tv_usec = 0)
#endif

#ifndef timerisset
#define timerisset(tvp)         ((tvp)->tv_sec || (tvp)->tv_usec)
#endif

#ifndef timerispositive
/// timeradd, timersub の結果として返された timeval 構造体が正の値を保持するか調べる.
/// それ以外の条件下での動作は保証しない.
#define timerispositive(tvp)         ((tvp)->tv_sec > 0 || (tvp)->tv_usec > 0)
#endif

#ifndef timerisnegative
/// timeradd, timersub の結果として返された timeval 構造体が負の値を保持するか調べる.
/// それ以外の条件下での動作は保証しない.
#define timerisnegative(tvp)         ((tvp)->tv_sec < 0 || (tvp)->tv_usec < 0)
#endif

#ifndef timercmp
#define timercmp(tvp, uvp, cmp)                                 \
        (((tvp)->tv_sec == (uvp)->tv_sec) ?                             \
            ((tvp)->tv_usec cmp (uvp)->tv_usec) :                       \
            ((tvp)->tv_sec cmp (uvp)->tv_sec))
#endif

#ifndef timeradd
#define timeradd(tvp, uvp, vvp)                                         \
        do {                                                            \
                (vvp)->tv_sec = (tvp)->tv_sec + (uvp)->tv_sec;          \
                (vvp)->tv_usec = (tvp)->tv_usec + (uvp)->tv_usec;       \
                if ((vvp)->tv_usec >= 1000000) {                        \
                        (vvp)->tv_sec++;                                \
                        (vvp)->tv_usec -= 1000000;                      \
                }                                                       \
        } while (0)
#endif

#ifndef timersub
#define timersub(tvp, uvp, vvp)                                         \
        do {                                                            \
                (vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;          \
                (vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;       \
                if ((vvp)->tv_usec < 0) {                               \
                        (vvp)->tv_sec--;                                \
                        (vvp)->tv_usec += 1000000;                      \
                }                                                       \
        } while (0)
#endif

#endif
