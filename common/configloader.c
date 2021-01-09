/*
 * Copyright (c) 2006-2014 Internet Initiative Japan Inc. All rights reserved.
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

#include <sys/stat.h>
#include <sys/types.h>
#include <ctype.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <syslog.h>
#include <assert.h>
#include <errno.h>
#include <getopt.h>

#include "ptrop.h"
#include "stdaux.h"
#include "fieldmask.h"
#include "keywordmap.h"
#include "xbuffer.h"
#include "loghandler.h"
#include "configloader.h"
#include "configtypes.h"

/**
 * 文字列型の設定項目を設定する
 *
 * @param entry
 * @param storage
 * @param value
 * @return true on success, false on failure.
 */
static bool
ConfigLoader_setString(const ConfigEntry *entry __attribute__((unused)), void *storage,
                       const char *value)
{
    char **char_pointer = storage;
    char *old_value = *char_pointer;
    *char_pointer = strdup(value);
    free(old_value);
    return true;
}   // end function: ConfigLoader_setString

/**
 * 符号付き整数型の設定項目を設定する.
 *
 * @param entry
 * @param storage
 * @param value
 * @return true on success, false on failure.
 */
static bool
ConfigLoader_setInt64(const ConfigEntry *entry, void *storage, const char *value)
{
    char *endptr;

    // 10進数を仮定して読み込む
    errno = 0;
    int64_t value64 = (int64_t) strtoll(value, &endptr, 10);

    if ((value64 == 0 && endptr == value) || 0 != errno) {
        // 値の形式が数値ではない
        goto parsefailed;
    }   // end if

    size_t value_size = strlen(value);
    if (value + value_size == endptr) {
        // 通常の整数値形式
    } else if (value + value_size == endptr + 1) {
        // 数値の後ろに単位が付いているかもしれない
        switch (*endptr) {
        case 'K':
            value64 *= 1024;
            break;
        case 'k':
            value64 *= 1000;
            break;
        case 'M':
            value64 *= (1024 * 1024);
            break;
        case 'm':
            value64 *= (1000 * 1000);
            break;
        case 'G':
            value64 *= (1024 * 1024 * 1024);
            break;
        case 'g':
            value64 *= (1000 * 1000 * 1000);
            break;
        default:
            goto parsefailed;
        }   // end switch
    } else {
        goto parsefailed;
    }   // end if

    int64_t *int_pointer = (int64_t *) storage;
    *int_pointer = (int64_t) value64;
    return true;

  parsefailed:
    LogError("failed to parse the config entry value: entry=%s, type=int64, value=%s", entry->name,
             value);
    return false;
}   // end function: ConfigLoader_setInt64

/**
 * 符号付なし整数型の設定項目を設定する.
 *
 * @param entry
 * @param storage
 * @param value
 * @return true on success, false on failure.
 */
static bool
ConfigLoader_setUint64(const ConfigEntry *entry, void *storage, const char *value)
{
    char *endptr;

    // 10進数を仮定して読み込む
    errno = 0;
    int64_t value64 = (int64_t) strtoll(value, &endptr, 10);

    if ((value64 == 0 && endptr == value) || 0 != errno || value64 < 0) {
        // 値の形式が数値ではない
        goto parsefailed;
    }   // end if

    size_t value_size = strlen(value);
    if (value + value_size == endptr) {
        // 通常の整数値形式
    } else if (value + value_size == endptr + 1) {
        // 数値の後ろに単位が付いているかもしれない
        switch (*endptr) {
        case 'K':
            value64 *= 1024;
            break;
        case 'k':
            value64 *= 1000;
            break;
        case 'M':
            value64 *= (1024 * 1024);
            break;
        case 'm':
            value64 *= (1000 * 1000);
            break;
        case 'G':
            value64 *= (1024 * 1024 * 1024);
            break;
        case 'g':
            value64 *= (1000 * 1000 * 1000);
            break;
        default:
            goto parsefailed;
        }   // end switch
    } else {
        goto parsefailed;
    }   // end if

    uint64_t *uint_pointer = (uint64_t *) storage;
    *uint_pointer = (uint64_t) value64;
    return true;

  parsefailed:
    LogError("failed to parse the config entry value: entry=%s, type=uint64, value=%s", entry->name,
             value);
    return false;
}   // end function: ConfigLoader_setUint64

/**
 * 時刻型の設定項目を設定する.
 *
 * @param entry
 * @param storage
 * @param value
 * @return true on success, false on failure.
 */
static bool
ConfigLoader_setTime(const ConfigEntry *entry, void *storage, const char *value)
{
    char *endptr;

    // 10進数を仮定して読み込む
    long time_value = strtol(value, &endptr, 10);

    if ((time_value == 0 && endptr == value) || time_value < 0) {
        // 値の形式が数値ではない
        goto parsefailed;
    }   // end if

    size_t value_size = strlen(value);
    if (value + value_size == endptr) {
        // 通常の整数値形式
    } else if (value + value_size == endptr + 1) {
        // 数値の後ろに単位が付いているかもしれない
        switch (*endptr) {
        case 'S':
        case 's':
            // do nothing
            break;
        case 'M':
        case 'm':
            time_value *= 60;
            break;
        case 'H':
        case 'h':
            time_value *= (60 * 60);
            break;
        case 'D':
        case 'd':
            time_value *= (24 * 60 * 60);
            break;
        case 'W':
        case 'w':
            time_value *= (7 * 24 * 60 * 60);
            break;
        default:
            goto parsefailed;
        }   // end switch
    } else {
        goto parsefailed;
    }   // end if

    time_t *uint_pointer = storage;
    *uint_pointer = (time_t) time_value;
    return true;

  parsefailed:
    LogError("failed to parse the config entry value: entry=%s, type=time, value=%s", entry->name,
             value);
    return false;
}   // end function: ConfigLoader_setTime

/**
 * 真偽値型の設定項目を設定する.
 *
 * @param entry
 * @param storage
 * @param value
 * @return true on success, false on failure.
 */
static bool
ConfigLoader_setBoolean(const ConfigEntry *entry, void *storage, const char *value)
{
    bool *bool_pointer = storage;

    if (0 == strcasecmp(value, "yes") || 0 == strcasecmp(value, "true") ||
        0 == strcasecmp(value, "1")) {
        *bool_pointer = true;
        return true;
    } else if (0 == strcasecmp(value, "no") || 0 == strcasecmp(value, "false") ||
               0 == strcasecmp(value, "0")) {
        *bool_pointer = false;
        return true;
    } else {
        LogError("failed to parse the config entry value: entry=%s, type=boolean, value=%s",
                 entry->name, value);
        return false;
    }   // end if
}   // end function: ConfigLoader_setBoolean

/**
 * 浮動小数点型の設定項目を設定する.
 *
 * @param entry
 * @param storage
 * @param value
 * @return true on success, false on failure.
 */
static bool
ConfigLoader_setDouble(const ConfigEntry *entry, void *storage, const char *value)
{
    char *endptr;
    double double_value = strtod(value, &endptr);
    if (endptr != value + strlen(value)) {
        LogError("failed to parse the config entry value: entry=%s, type=double, value=%s",
                 entry->name, value);
        return false;
    }   // end if
    double *double_pointer = storage;
    *double_pointer = double_value;
    return true;
}   // end function: ConfigLoader_setDouble

static const KeywordMap syslog_facility_table[] = {
// generic facilities
    {"KERN", LOG_KERN},
    {"USER", LOG_USER},
    {"MAIL", LOG_MAIL},
    {"DAEMON", LOG_DAEMON},
    {"AUTH", LOG_AUTH},
    {"SYSLOG", LOG_SYSLOG},
    {"LPR", LOG_LPR},
    {"NEWS", LOG_NEWS},
    {"UUCP", LOG_UUCP},
    {"CRON", LOG_CRON},
    {"LOCAL0", LOG_LOCAL0},
    {"LOCAL1", LOG_LOCAL1},
    {"LOCAL2", LOG_LOCAL2},
    {"LOCAL3", LOG_LOCAL3},
    {"LOCAL4", LOG_LOCAL4},
    {"LOCAL5", LOG_LOCAL5},
    {"LOCAL6", LOG_LOCAL6},
    {"LOCAL7", LOG_LOCAL7},
// FreeBSD
#ifdef LOG_AUTHPRIV
    {"AUTHPRIV", LOG_AUTHPRIV},
#endif
#ifdef LOG_FTP
    {"FTP", LOG_FTP},
#endif
#ifdef LOG_NTP
    {"NTP", LOG_NTP},
#endif
#ifdef LOG_SECURITY
    {"SECURITY", LOG_SECURITY},
#endif
#ifdef LOG_CONSOLE
    {"CONSOLE", LOG_CONSOLE},
#endif
// Solaris
#ifdef LOG_AUDIT
    {"AUDIT", LOG_AUDIT},
#endif
    {NULL, -1}, // sentinel
};

/**
 * syslog facility 型の設定項目を設定する.
 *
 * @param entry
 * @param storage
 * @param value
 * @return true on success, false on failure.
 */
static bool
ConfigLoader_setSyslogFacility(const ConfigEntry *entry, void *storage, const char *value)
{
    int facility_value = KeywordMap_lookupByCaseString(syslog_facility_table, value);
    if (-1 == facility_value) {
        LogError("failed to parse the config entry value: entry=%s, type=syslog_facility, value=%s",
                 entry->name, value);
        return false;
    }   // end if
    int *facility_pointer = storage;
    *facility_pointer = facility_value;
    return true;
}   // end function: ConfigLoader_setSyslogFacility

static const KeywordMap log_level_table[] = {
    {"EMERG", LOG_EMERG},
    {"ALERT", LOG_ALERT},
    {"CRIT", LOG_CRIT},
    {"ERR", LOG_ERR},
    {"WARNING", LOG_WARNING},
    {"NOTICE", LOG_NOTICE},
    {"INFO", LOG_INFO},
    {"DEBUG", LOG_DEBUG},
    {NULL, -1}, // sentinel
};

/**
 * log level 型の設定項目を設定する.
 *
 * @param entry
 * @param storage
 * @param value
 * @return true on success, false on failure.
 */
static bool
ConfigLoader_setLogLevel(const ConfigEntry *entry, void *storage, const char *value)
{
    int log_level_value = KeywordMap_lookupByCaseString(log_level_table, value);
    if (-1 == log_level_value) {
        LogError("failed to parse the config entry value: entry=%s, type=log_level, value=%s",
                 entry->name, value);
        return false;
    }   // end if
    int *log_level_pointer = storage;
    *log_level_pointer = log_level_value;
    return true;
}   // end function: ConfigLoader_setLogLevel

static const KeywordMap vdmarc_verification_mode_table[] = {
    {"strict", VDMARC_VERIFICATION_MODE_STRICT},
    {"relax", VDMARC_VERIFICATION_MODE_RELAX},
    {"none", VDMARC_VERIFICATION_MODE_NONE},
    {NULL, -1}, // sentinel
};

/**
 * vdmarc verification mode 型の設定項目を設定する.
 *
 * @param entry
 * @param storage
 * @param value
 * @return true on success, false on failure.
 */
static bool
ConfigLoader_setVdmarcVerificationMode(const ConfigEntry *entry, void *storage, const char*value)
{
    int vdmarc_verification_mode = KeywordMap_lookupByCaseString(vdmarc_verification_mode_table, value);
    if (-1 == vdmarc_verification_mode) {
        LogError("failed to parse the config entry value: entry=%s, type=vdmarc_verification_mode, value=%s",
                 entry->name, value);
        return false;
    }   // end if
    int *vdmarc_verification_mode_pointer = storage;
    *vdmarc_verification_mode_pointer = vdmarc_verification_mode;
    return true;
}   // end function: ConfigLoader_setVdmarcVerificationMode

/**
 * 設定項目に値を設定する.
 *
 * @param config
 * @param entry
 * @param value
 * @return true on success, false on failure.
 */
static bool
ConfigLoader_setEntryValue(ConfigStorageBase *config, const ConfigEntry *entry, const char *value)
{
    assert(NULL != config);
    assert(NULL != entry);

    ptrdiff_t entry_no = entry - (*config->config_table);
    if (FIELD_ISSET(entry_no, &config->filled_mask)) {
        return true;
    }   // end if

    void *storage = STRUCT_MEMBER_P(config, entry->offset);

    bool set_stat = false;
    switch (entry->value_type) {
    case CONFIG_TYPE_STRING:
        set_stat = ConfigLoader_setString(entry, storage, value);
        break;
    case CONFIG_TYPE_INT64:
        set_stat = ConfigLoader_setInt64(entry, storage, value);
        break;
    case CONFIG_TYPE_UINT64:
        set_stat = ConfigLoader_setUint64(entry, storage, value);
        break;
    case CONFIG_TYPE_BOOLEAN:
        set_stat = ConfigLoader_setBoolean(entry, storage, value);
        break;
    case CONFIG_TYPE_DOUBLE:
        set_stat = ConfigLoader_setDouble(entry, storage, value);
        break;
    case CONFIG_TYPE_TIME:
        set_stat = ConfigLoader_setTime(entry, storage, value);
        break;
    case CONFIG_TYPE_SYSLOG_FACILITY:
        set_stat = ConfigLoader_setSyslogFacility(entry, storage, value);
        break;
    case CONFIG_TYPE_LOG_LEVEL:
        set_stat = ConfigLoader_setLogLevel(entry, storage, value);
        break;
    case CONFIG_TYPE_VDMARC_VERIFICATION_MODE:
        set_stat = ConfigLoader_setVdmarcVerificationMode(entry, storage, value);
        break;
    default:
        LogError("unknown config entry type: type=%d, entry=%s", entry->value_type, entry->name);
        return false;
    }   // end switch

    if (set_stat) {
        FIELD_SET(entry_no, &config->filled_mask);
    }   // end if
    return set_stat;
}   // end function: ConfigLoader_setEntryValue

/**
 * 指定された設定項目に対応するエントリを返す.
 *
 * @param name 設定項目名
 * @return 設定項目に対応するConfigEntry構造体へのポインタ,
 *         対応する設定項目がない場合はNULL.
 */
static const ConfigEntry *
ConfigLoader_lookupEntry(const ConfigEntry *entry, const char *name)
{
    assert(NULL != entry);
    assert(NULL != name);

    for (const ConfigEntry *p = entry; NULL != p->name; p++) {
        if (0 == strcasecmp(p->name, name)) {
            return p;
        }   // end if
    }   // end for
    return NULL;
}   // end function: ConfigLoader_lookupEntry

/**
 * 設定項目に値を設定する
 *
 * @param config
 * @param name 設定項目名.
 * @param value 設定項目の値.
 * @return true on success, false on failure.
 */
bool
ConfigLoader_setValue(ConfigStorageBase *config, const char *name, const char *value)
{
    assert(NULL != config);
    assert(NULL != name);
    assert(NULL != value);

    const ConfigEntry *entry = ConfigLoader_lookupEntry(*config->config_table, name);
    if (NULL != entry) {
        return ConfigLoader_setEntryValue(config, entry, value);
    } else {
        LogError("undefined config entry: entry=%s, value=%s", name, value);
        return false;
    }   // end if
}   // end function: ConfigLoader_setValue

static void *
ConfigLoader_getValue(const ConfigStorageBase *config, const char *name, ConfigType type)
{
    assert(NULL != config);
    assert(NULL != name);

    const ConfigEntry *entry = ConfigLoader_lookupEntry(*config->config_table, name);
    if (NULL != entry) {
        if (type == entry->value_type) {
            assert(NULL != entry);
            return STRUCT_MEMBER_P(config, entry->offset);
        } else {
            LogWarning("config value reference violation: entry=%s, error=type_mismatch", name);
            return NULL;
        }   // end if
    }   // end if

    LogWarning("config value reference violation: entry=%s, error=undefined_entry", name);
    return NULL;
}   // end function: ConfigLoader_getValue

/**
 * 文字列型の設定項目の値を取得する.
 *
 * @param config
 * @param name 設定項目名.
 * @return 設定項目の値, 失敗した場合はNULLを返す.
 */
const char *
ConfigLoader_getStringValue(const ConfigStorageBase *config, const char *name)
{
    char **char_pointer = ConfigLoader_getValue(config, name, CONFIG_TYPE_STRING);
    return *char_pointer;
}   // end function: ConfigLoader_getStringValue

/**
 * UINT64型の設定項目の値を取得する.
 *
 * @param config
 * @param name 設定項目名.
 * @return 設定項目の値, 失敗した場合はerrorに値を設定する.
 */
uint64_t
ConfigLoader_getUint64Value(const ConfigStorageBase *config, const char *name)
{
    return *(uint64_t *) ConfigLoader_getValue(config, name, CONFIG_TYPE_UINT64);
}   // end function: ConfigLoader_getUint64Value

static void
ConfigLoader_lstrip(char **phead, const char *tail)
{
    for (; *phead < tail && 0 != isspace(**phead); ++(*phead));
}   // end function: ConfigLoader_lstrip

static void
ConfigLoader_rstrip(const char *head, char **ptail)
{
    for (; head < *ptail && 0 != isspace(*((*ptail) - 1)); --(*ptail));
}   // end function: ConfigLoader_rstrip

static void
ConfigLoader_strip(char **phead, char **ptail)
{
    ConfigLoader_rstrip(*phead, ptail);
    ConfigLoader_lstrip(phead, *ptail);
}   // end function: ConfigLoader_strip

/**
 * 設定ファイルから設定項目を読み込む
 * @param filename 設定ファイル名.
 * @return true on success, false on failure.
 */
bool
ConfigLoader_loadFile(ConfigStorageBase *config, const char *filename)
{
    assert(NULL != config);
    assert(NULL != filename);

    FILE *fp;
    char buf[LINE_MAX];

    if (NULL == (fp = fopen(filename, "r"))) {
        LogError("failed to open configuration file: filename=%s, errno=%s", filename,
                 strerror(errno));
        return false;
    }   // end if

    LogInfo("loading config %s ...", filename);
    while (NULL != fgets(buf, LINE_MAX, fp)) {
        char *bufhead = buf;
        char *buftail = STRTAIL(buf);
        ConfigLoader_strip(&bufhead, &buftail);
        *buftail = '\0';

        if ('#' == bufhead[0] || bufhead == buftail) {
            continue;
        }   // end if

        char *keyhead = bufhead;
        char *keytail = strchr(keyhead, ':');
        if (NULL == keytail) {
            (void) fclose(fp);
            return false;
        }   // end if
        char *valuehead = keytail + 1;  // save the position of delimiter before ConfigLoader_rstrip

        ConfigLoader_rstrip(keyhead, &keytail);
        *keytail = '\0';

        if (buftail <= valuehead) {
            (void) fclose(fp);
            return false;
        }   // end if

        ConfigLoader_lstrip(&valuehead, buftail);
        if (!ConfigLoader_setValue(config, keyhead, valuehead)) {
            (void) fclose(fp);
            return false;
        }   // end if
    }   // end while

    (void) fclose(fp);
    return true;
}   // end function: ConfigLoader_loadFile

/**
 * @return true on success, false on failure.
 */
bool
ConfigLoader_loadDirectory(ConfigStorageBase *config, const char *dirname)
{
    // readdir_r で使用する構造体用のメモリを確保
    long direntsize = pathconf(dirname, _PC_NAME_MAX);
    if (direntsize == -1) {
        LogError("pathconf failed: errno=%s", strerror(errno));
        return false;
    }   // end if
    direntsize += offsetof(struct dirent, d_name) +1;
    struct dirent *dirbuf = (struct dirent *) malloc(direntsize);
    if (NULL == dirbuf) {
        LogNoResource();
        return false;
    }   // end if

    /*
     * pathconf() と opendir() の間に basedir の指すディレクトリが変わる可能性があり,
     * この方法は一般的には安全ではない.
     * 例えば Linux なら opendir() してから dirfd() と fpathconf() を組み合わせるのが安全なのだが,
     * Solaris には dirfd() がないので, dp->d_fd というように決め打ちをしなければならない.
     */

    DIR *dp = opendir(dirname);
    if (NULL == dp) {
        LogError("failed to open directory: directory=%s, errno=%s", dirname, strerror(errno));
        free(dirbuf);
        return false;
    }   // end if

    int ret = 0;
    struct dirent *dirp;
    while (0 == (ret = readdir_r(dp, dirbuf, &dirp)) && NULL != dirp) {
        struct stat stbuf;
        char path[PATH_MAX];

        if ('.' == dirp->d_name[0]) {
            continue;   // just ignore
        }   // end if

        snprintf(path, PATH_MAX, "%s/%s", dirname, dirp->d_name);
        SKIP_EINTR(ret = stat(path, &stbuf));
        if (ret < 0) {
            break;
        }   // end if

        if (S_ISREG(stbuf.st_mode)) {
            if (!ConfigLoader_loadFile(config, path)) {
                break;
            }   // end if
        }   // end if
    }   // end while

    SKIP_EINTR(closedir(dp));
    free(dirbuf);

    return bool_cast(0 == ret);
}   // end function: ConfigLoader_loadDirectory

/**
 * @return true on success, false on failure.
 */
bool
ConfigLoader_load(ConfigStorageBase *config, const char *path)
{
    struct stat stbuf;
    int ret;
    SKIP_EINTR(ret = stat(path, &stbuf));
    if (ret < 0) {
        LogError("cannot access: path=%s, errno=%s", path, strerror(errno));
        return false;
    }   // end if
    if (S_ISREG(stbuf.st_mode)) {
        return ConfigLoader_loadFile(config, path);
    } else if (S_ISDIR(stbuf.st_mode)) {
        return ConfigLoader_loadDirectory(config, path);
    } else {
        LogError("unexpected file type: path=%s", path);
        return false;
    }   // end if
}   // end function: ConfigLoader_load

/**
 * 設定項目にデフォルト値を設定する.
 */
void
ConfigLoader_applyDefaultValue(ConfigStorageBase *config)
{
    assert(NULL != config);

    for (const ConfigEntry *p = *config->config_table; NULL != p->name; ++p) {
        if (NULL != p->default_value) {
            if (!ConfigLoader_setEntryValue(config, p, p->default_value)) {
                LogError("invalid default config: entry=%s, value=%s", p->name, p->default_value);
            }   // end if
        }   // end if
    }   // end for
}   // end function: ConfigLoader_applyDefaultValue

void
ConfigLoader_cleanup(ConfigStorageBase *config)
{
    assert(NULL != config);

    for (const ConfigEntry *p = *config->config_table; NULL != p->name; ++p) {
        void *value = (void *) STRUCT_MEMBER_P(config, p->offset);
        if (CONFIG_TYPE_STRING == p->value_type) {
            char **j = (char **) value;
            free(*j);
            *j = NULL;
        }   // end if
    }   // end for
}   // end function: ConfigLoader_cleanup

void
ConfigLoader_dump(const ConfigStorageBase *config)
{
    LogPlain("[configuration]");
    for (const ConfigEntry *p = *config->config_table; NULL != p->name; ++p) {
        void *value = STRUCT_MEMBER_P(config, p->offset);

        switch (p->value_type) {
        case CONFIG_TYPE_STRING:
            LogPlain("  %s: %s", p->name, PTROR(*(char **) value, "(empty)"));
            break;

        case CONFIG_TYPE_BOOLEAN:
            LogPlain("  %s: %s", p->name, *(bool *) value ? "true" : "false");
            break;

        case CONFIG_TYPE_INT64:
            LogPlain("  %s: %" PRId64, p->name, *(int64_t *) value);
            break;

        case CONFIG_TYPE_UINT64:
            LogPlain("  %s: %" PRIu64, p->name, *(uint64_t *) value);
            break;

        case CONFIG_TYPE_TIME:
            LogPlain("  %s: %ld", p->name, (long) *(time_t *) value);
            break;

        case CONFIG_TYPE_DOUBLE:
            LogPlain("  %s: %e", p->name, *(double *) value);
            break;

        case CONFIG_TYPE_SYSLOG_FACILITY:;
            const char *facility_name =
                KeywordMap_lookupByValue(syslog_facility_table, *(int *) value);
            LogPlain("  %s: %s", p->name, PTROR(facility_name, "(empty)"));
            break;

        case CONFIG_TYPE_VDMARC_VERIFICATION_MODE:;
            const char *vdmarc_verification_mode_name =
                KeywordMap_lookupByValue(vdmarc_verification_mode_table, *(int *) value);
            LogPlain("  %s: %s", p->name, PTROR(vdmarc_verification_mode_name, "(empty)"));
            break;

        default:
            break;
        }   // end switch
    }   // end for
}   // end function: ConfigLoader_dump
