#ifndef LOGGER_H
#define LOGGER_H

#include "platform.h"
#include "config.h" // Needs config_t for initialization

/* Log levels */
typedef enum {
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR
} LogLevel;

/* Asynchronous log function - use this macro */
#define LOG(level, format, ...) \
    logger_queue_log(level, __FILE__, __LINE__, __func__, format, ##__VA_ARGS__)

/* Internal function, use LOG macro instead */
void logger_queue_log(LogLevel level, const char *file, int line, const char *func, const char *format, ...);

/* Logger initialization and shutdown */
void logger_init(const config_t *cfg, const char *progname);
void logger_close(void);

#endif // LOGGER_H