/*
 * Copyright (c) 2008-2015 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifndef __YENMA_SESSION_H__
#define __YENMA_SESSION_H__

#include <stdbool.h>
#include <netinet/in.h>
#include <libmilter/mfapi.h>

#include "intarray.h"
#include "inetmailbox.h"
#include "inetmailheaders.h"
#include "socketaddress.h"
#include "dnsresolv.h"
#include "validatedresult.h"
#include "authresult.h"
#include "yenma.h"
#include "yenmacontext.h"
#include "yenmaconfig.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct YenmaSession {
// per connection
    YenmaContext *ctx;
    DnsResolver *resolver;
    bool keep_leading_header_space;
    _SOCK_ADDR *hostaddr;
    char *helohost;
    char ipaddr[MAX_NUMERICINFO_LEN + 1];
// per message
    SpfEvaluator *spfevaluator;
    SpfEvaluator *sidfevaluator;
    DkimVerifier *verifier;
    DmarcAligner *aligner;
    InetMailHeaders *headers;
    InetMailbox *envfrom;
    char *raw_envfrom;          // store the raw envelope from address (without mail-param)
    char *qid;
    AuthResult *authresult;
    ValidatedResult *validated_result;  // the storage of authentication results

    // the attributes to delete the Authentication-Results header(s)
    int authhdr_count;          // the number of Authentication-Results headers
    IntArray *delauthhdr;       // the array of the indexes of Authentication-Results headers to delete
} YenmaSession;

extern YenmaSession *YenmaSession_new(YenmaContext *yenmactx);
extern void YenmaSession_reset(YenmaSession *self);
extern void YenmaSession_free(YenmaSession *self);

#ifdef __cplusplus
}
#endif

#endif /* __YENMA_SESSION_H__ */
