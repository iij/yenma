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

#ifndef __CONFIG_LOADER_H__
#define __CONFIG_LOADER_H__

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include "fieldmask.h"

#ifdef __cplusplus
extern "C" {
#endif

// enumeration of the config entry types
typedef enum {
    CONFIG_TYPE_NULL,
    CONFIG_TYPE_BOOLEAN,        // true, false (bool)
    CONFIG_TYPE_STRING,         // string (char *)
    CONFIG_TYPE_INT64,          // 64bit signed integer (int64_t)
    CONFIG_TYPE_UINT64,         // 64bit unsigned integer (uint64_t)
    CONFIG_TYPE_DOUBLE,         // double
    CONFIG_TYPE_TIME,           // time_t
    CONFIG_TYPE_SYSLOG_FACILITY,    // syslog facility (int)
    CONFIG_TYPE_LOG_LEVEL,      // log level (int)
    CONFIG_TYPE_VDMARC_VERIFICATION_MODE, // vdmarc verification mode (int)
} ConfigType;

typedef struct ConfigEntry {
    // name of the config entry
    const char *name;
    // type of the config entry
    ConfigType value_type;
    // default value
    const char *default_value;
    // offset to the variable
    size_t offset;
    // description of the config entry
    const char *description;
} ConfigEntry;

#define ConfigStorageBase_MEMBER            \
    const ConfigEntry (*config_table)[];    \
    field_set filled_mask

typedef struct ConfigStorageBase {
    ConfigStorageBase_MEMBER;
} ConfigStorageBase;

extern bool ConfigLoader_setValue(ConfigStorageBase *config, const char *name, const char *value);
extern const char *ConfigLoader_getStringValue(const ConfigStorageBase *config, const char *name);
extern uint64_t ConfigLoader_getUint64Value(const ConfigStorageBase *config, const char *name);
extern bool ConfigLoader_loadFile(ConfigStorageBase *config, const char *filename);
extern bool ConfigLoader_loadDirectory(ConfigStorageBase *config, const char *dirname);
extern bool ConfigLoader_load(ConfigStorageBase *config, const char *path);
extern void ConfigLoader_applyDefaultValue(ConfigStorageBase *config);
extern void ConfigLoader_cleanup(ConfigStorageBase *config);
extern void ConfigLoader_dump(const ConfigStorageBase *config);

#ifdef __cplusplus
}
#endif

#endif // __CONFIG_LOADER_H__
