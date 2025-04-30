#ifndef UTILS_H
#define UTILS_H

#include "platform.h"

/* Safe String Wrappers */
size_t safe_strlcpy(char *dst, const char *src, size_t dstsize, const char *context);
int safe_snprintf(char *buf, size_t bufsize, const char *context, const char *fmt, ...);

/* Time Helper */
uint64_t get_current_time_ms(void);

/* Sleep Helper */
void msleep(unsigned int milliseconds);

#endif // UTILS_H