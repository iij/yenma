/*
 * Copyright (c) 2007-2014 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifndef __SPF_EVALUATOR_H__
#define __SPF_EVALUATOR_H__

#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>

#include "xbuffer.h"
#include "strarray.h"
#include "inetmailbox.h"
#include "dnsresolv.h"
#include "spf.h"
#include "spfevalpolicy.h"

struct SpfEvaluator {
    const SpfEvalPolicy *policy;
    SpfRecordScope scope;       // evaluation scope: SPF1, SPF2_MFROM or SPF2_PRA
    sa_family_t sa_family;
    union ipaddr46 {
        struct in_addr addr4;
        struct in6_addr addr6;
    } ipaddr;
    /*
     * true if domain portion of the "MAIL FROM" is chosen as <domain> argument of check_host() function,
     * false if "HELO" identity is chosen (SPF-scope only)
     */
    bool is_sender_context;
    StrArray *domain;
    char *helo_domain;
    InetMailbox *sender;
    unsigned int dns_mech_count;    // the number of mechanisms which involves DNS lookups encountered during the evaluation
    unsigned int void_lookup_count; // the number of void lookups encountered during the evaluation
    unsigned int redirect_depth;    // the depth of "redirect=" modifier
    unsigned int include_depth; // the depth of "include:" mechanism
    bool local_policy_mode;     // true while evaluating local-policy, to prevent infinite loop
    XBuffer *xbuf;
    DnsResolver *resolver;      // reference to the DnsResolver object
    SpfScore score;             /// final score (as cache)
    char *explanation;          // explanation string provided by "exp=" modifier at "fail" (="hardfail") result
};

extern const char *SpfEvaluator_getDomain(const SpfEvaluator *self);
extern int SpfEvaluator_isValidatedDomainName(const SpfEvaluator *self, const char *revdomain);

#endif /* __SPF_EVALUATOR_H__ */
