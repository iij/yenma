/*
 * Copyright (c) 2006-2015 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id$
 */

#ifndef __CONFIGTYPES_H__
#define __CONFIGTYPES_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  VDMARC_VERIFICATION_MODE_STRICT, // "strict"
  VDMARC_VERIFICATION_MODE_RELAX,  // "relax"
  VDMARC_VERIFICATION_MODE_NONE,   // "none"
} VdmarcVerificationMode;

#ifdef __cplusplus
}
#endif

#endif // __CONFIGTYPES_H__
