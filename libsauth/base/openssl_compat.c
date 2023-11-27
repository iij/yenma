/*
 * Copyright (c) 2023 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <openssl/err.h>

#include "loghandler.h"

#if OPENSSL_VERSION_NUMBER < 0x30000000L

void
OpenSSL_logErrors(void)
{
    unsigned long errinfo;
    const char *errfilename, *errstr;
    int errline, errflags;

    while (0 != (errinfo = ERR_get_error_line_data(&errfilename, &errline, &errstr, &errflags))) {
        LogError("[OpenSSL] module=%s, function=%s, reason=%s",
                        ERR_lib_error_string(errinfo), ERR_func_error_string(errinfo),
                        ERR_reason_error_string(errinfo));
        LogError("[OpenSSL] file=%s, line=%d, error=%s", errfilename, errline,
                        (errflags & ERR_TXT_STRING) ? errstr : "(none)");
    }   // end while
}   // end function: OpenSSL_logErrors

#else

void
OpenSSL_logErrors(void)
{
    unsigned long errinfo;
    const char *errfilename, *errstr, *errfunc;
    int errline, errflags;

    while (0 != (errinfo = ERR_get_error_all(&errfilename, &errline, &errfunc, &errstr, &errflags))) {
                LogError("[OpenSSL] code=%08lX, module=%s, reason=%s",
                                errinfo, ERR_lib_error_string(errinfo), ERR_reason_error_string(errinfo));
                LogError("[OpenSSL] file=%s, func=%s, line=%d, error=%s", errfilename, errfunc, errline,
                                (errflags & ERR_TXT_STRING) ? errstr : "(none)");
    }   // end while
}   // end function: OpenSSL_logErrors

#endif
