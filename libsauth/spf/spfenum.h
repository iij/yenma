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

#ifndef __SPF_ENUM_H__
#define __SPF_ENUM_H__

#include "spf.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum SpfQualifier {
    SPF_QUALIFIER_NULL = 0,
    SPF_QUALIFIER_PLUS = SPF_SCORE_PASS,
    SPF_QUALIFIER_MINUS = SPF_SCORE_FAIL,
    SPF_QUALIFIER_QUESTION = SPF_SCORE_NEUTRAL,
    SPF_QUALIFIER_TILDE = SPF_SCORE_SOFTFAIL,
} SpfQualifier;

typedef enum SpfTermType {
    SPF_TERM_MECH_NULL = 0,
    SPF_TERM_MECH_ALL,
    SPF_TERM_MECH_INCLUDE,
    SPF_TERM_MECH_A,
    SPF_TERM_MECH_MX,
    SPF_TERM_MECH_PTR,
    SPF_TERM_MECH_IP4,
    SPF_TERM_MECH_IP6,
    SPF_TERM_MECH_EXISTS,
    SPF_TERM_MOD_REDIRECT,
    SPF_TERM_MOD_EXPLANATION,
    SPF_TERM_MOD_UNKNOWN,
} SpfTermType;

typedef enum SpfMechanismType {
    SPF_MECHANISM_NULL = 0,
    SPF_MECHANISM_ALL = SPF_TERM_MECH_ALL,
    SPF_MECHANISM_INCLUDE = SPF_TERM_MECH_INCLUDE,
    SPF_MECHANISM_A = SPF_TERM_MECH_A,
    SPF_MECHANISM_MX = SPF_TERM_MECH_MX,
    SPF_MECHANISM_PTR = SPF_TERM_MECH_PTR,
    SPF_MECHANISM_IP4 = SPF_TERM_MECH_IP4,
    SPF_MECHANISM_IP6 = SPF_TERM_MECH_IP6,
    SPF_MECHANISM_EXISTS = SPF_TERM_MECH_EXISTS,
} SpfMechanismType;

typedef enum SpfModifierType {
    SPF_MODIFIER_NULL = 0,
    SPF_MODIFIER_REDIRECT = SPF_TERM_MOD_REDIRECT,
    SPF_MODIFIER_EXPLANATION = SPF_TERM_MOD_EXPLANATION,
    SPF_MODIFIER_UNKNOWN = SPF_TERM_MOD_UNKNOWN,
} SpfModifierType;

typedef enum SpfMacroLetter {
    SPF_MACRO_NULL = 0,
    SPF_MACRO_S_SENDER,
    SPF_MACRO_L_SENDER_LOCALPART,
    SPF_MACRO_O_SENDER_DOMAIN,
    SPF_MACRO_D_DOMAIN,
    SPF_MACRO_I_DOTTED_IPADDR,
    SPF_MACRO_P_IPADDR_VALID_DOMAIN,
    SPF_MACRO_V_REVADDR_SUFFIX,
    SPF_MACRO_H_HELO_DOMAIN,
    SPF_MACRO_C_TEXT_IPADDR,
    SPF_MACRO_R_CHECKING_DOMAIN,
    SPF_MACRO_T_TIMESTAMP,
} SpfMacroLetter;

typedef enum SpfTermParamType {
    SPF_TERM_PARAM_NONE,
    SPF_TERM_PARAM_DOMAINSPEC,
    SPF_TERM_PARAM_IP4,
    SPF_TERM_PARAM_IP6,
} SpfTermParamType;

#ifdef __cplusplus
}
#endif

#endif /* __SPF_ENUM_H__ */
