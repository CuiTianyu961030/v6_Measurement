#ifndef MESA_HANDLE__LOGGER_H
#define MESA_HANDLE__LOGGER_H

/*
 * runtime_log with handle,
 * based on runtime_log.
 * yang wei
 * create time:2014-03-24
 * version:20140324
 */

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define RLOG_LV_DEBUG       10
#define RLOG_LV_INFO        20
#define RLOG_LV_FATAL       30


#define MESA_HANDLE_RUNTIME_LOG(handle, lv, mod, fmt, args...)   \
    MESA_handle_runtime_log((handle), (lv), (mod), "file %s, line %d, " fmt, \
                       __FILE__, __LINE__, ##args)

/*
 * name: MESA_create_runtime_log_handle
 * functionality: get runtime_log handle;
 * params:
 *  file_path: path of log file;
 *  level: level of log;
 * returns:
 *  not NULL, if succeeded;
 *   NULL, if file is not absolute path, or failed to create log file;
 */
void *MESA_create_runtime_log_handle(const char *file_path, int level);

/*
 * name: MESA_handle_runtime_log
 * functionality: appends log message to runtime log file;
 * params:
 *   handle:handle of runtime log, which is created by MESA_create_runtime_log_handle;
 *  level: log level, messages with level value smaller the global var
 *      "runtime_log_level" are ignored;
 *  module: name of loggin module;
 *  fmt: format string;
 * returns:
 *  none;
 */
void MESA_handle_runtime_log(void *handle, int level, const char *module, const char *fmt, ...);

/*
 * name: MESA_destroy_runtime_log_handle
 * functionality: release runtime log handle memory.
 * params:
 *  handle: runtime log handle which is going to be released;
 * returns:
 *  none;
 */
void MESA_destroy_runtime_log_handle(void *handle);

#ifdef __cplusplus
}
#endif

#endif


