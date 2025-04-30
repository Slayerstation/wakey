#include "utils.h"

/* --------------------- Safe String Wrappers --------------------- */
static size_t my_strlcpy(char *dst, const char *src, size_t dstsize) {
    size_t srclen = strlen(src);
    if (dstsize) {
        size_t copylen = (srclen >= dstsize) ? dstsize - 1 : srclen;
        memcpy(dst, src, copylen);
        dst[copylen] = '\0';
    }
    return srclen;
}

size_t safe_strlcpy(char *dst, const char *src, size_t dstsize, const char *context) {
    size_t result = my_strlcpy(dst, src, dstsize);
    if (result >= dstsize) {
        fprintf(stderr, "WARNING in %s: string truncated. Source: \"%s\", Buffer size: %zu, Attempted length: %zu\n",
                context, src, dstsize, result);
    }
    return result;
}

int safe_snprintf(char *buf, size_t bufsize, const char *context, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(buf, bufsize, fmt, args);
    va_end(args);
    if (n < 0 || (size_t)n >= bufsize) {
        fprintf(stderr, "WARNING in %s: snprintf truncation or error. Buffer size: %zu, Required: %d\n", context, bufsize, n);
    }
    return n;
}

/* --------------------- Helper: Get Current Time in Milliseconds --------------------- */
#ifdef _WIN32
uint64_t get_current_time_ms(void) {
    return GetTickCount64();
}
#else
uint64_t get_current_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return ((uint64_t)tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}
#endif

/* --------------------- Sleep Helper --------------------- */
void msleep(unsigned int milliseconds) {
#ifdef _WIN32
    Sleep(milliseconds);
#else
    usleep(milliseconds * 1000);
#endif
}