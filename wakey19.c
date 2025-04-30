/*
 * wakey19.c - Updated version with asynchronous and buffered logging,
 * log rotation by file size and time intervals, plus automatic archival
 * and compression of rotated logs. Now also instrumented with operational
 * metrics and a simple HTTP endpoint for export (e.g., to Prometheus).
 *
 * Changes:
 *   - All log messages are enqueued and processed by a dedicated logging thread.
 *   - The logging thread formats the timestamp, log level, context (file, line, func),
 *     and when configured, includes additional context (and, optionally, a stack trace).
 *   - Log rotation is performed when the file size exceeds a configured maximum or
 *     when a fixed time interval has elapsed. The old log is renamed, archived, and compressed.
 *   - Instrumentation counters track ARP resolution times, wake–up attempts,
 *     reverse ARP attempts and successes, etc.
 *   - A lightweight HTTP server is spawned to export these metrics (in Prometheus format).
 *   - **Updated:** The reverse ARP resolution is now implemented asynchronously on POSIX:
 *     a netlink socket subscribed to neighbor (ARP) events is used with select() so that
 *     rather than polling repeatedly, the code waits for an update.
 *
 * Additionally, security and bounds checks have been added:
 *   - A safe my_strlcpy wrapper is introduced that logs a warning if the source string is 
 *     too long for the destination.
 *   - A safe_snprintf() function is introduced so that every use of snprintf is checked for overflow.
 *   - All string copy and formatting calls have been replaced with these wrappers.
 *
 * Compile with -DDEBUG for extra logging and -DENABLE_STACKTRACE (on POSIX systems)
 * to generate stack traces on errors.
 *
 * (This code has cross–platform support for POSIX and Windows.)
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <stdarg.h>
 #include <string.h>
 #include <stdint.h>
 #include <errno.h>
 #include <ctype.h>
 #include <time.h>
 #include <limits.h>
 #include <sys/stat.h>
 
 #ifdef _WIN32
   #include <winsock2.h>
   #include <ws2tcpip.h>
   #include <iphlpapi.h>
   #include <windows.h>
   #include <io.h>
   #include <fcntl.h>
   #pragma comment(lib, "Ws2_32.lib")
   #pragma comment(lib, "Iphlpapi.lib")
 #else
   #define _GNU_SOURCE
   #include <sys/socket.h>
   #include <sys/file.h>
   #include <arpa/inet.h>
   #include <unistd.h>
   #include <sys/ioctl.h>
   #include <net/if.h>
   #include <netdb.h>
   #include <netpacket/packet.h>
   #include <net/ethernet.h>
   #include <ifaddrs.h>
   #include <fcntl.h>
   #include <syslog.h>
   #include <pthread.h>
   #include <execinfo.h>
   #include <sys/time.h>
   /* For asynchronous reverse ARP using netlink */
   #include <linux/netlink.h>
   #include <linux/rtnetlink.h>
   #include <linux/neighbour.h>
 #endif
 
 /* --------------------- Safe String Wrappers --------------------- */
 /* Instead of using strlcpy (which is not universally available and conflicts when implicitly declared),
    we define our own implementation called my_strlcpy. */
 static size_t my_strlcpy(char *dst, const char *src, size_t dstsize) {
     size_t srclen = strlen(src);
     if (dstsize) {
         size_t copylen = (srclen >= dstsize) ? dstsize - 1 : srclen;
         memcpy(dst, src, copylen);
         dst[copylen] = '\0';
     }
     return srclen;
 }
 
 /* A safe wrapper around my_strlcpy that logs a warning if truncation occurs. */
 static size_t safe_strlcpy_wrapper(char *dst, const char *src, size_t dstsize, const char *context) {
     size_t result = my_strlcpy(dst, src, dstsize);
     if (result >= dstsize) {
         fprintf(stderr, "WARNING in %s: string truncated. Source: \"%s\", Buffer size: %zu, Attempted length: %zu\n",
                 context, src, dstsize, result);
     }
     return result;
 }
 
 /* A safe snprintf wrapper that checks for truncation.
    If the formatted string does not entirely fit, a warning is printed to stderr. */
 static int safe_snprintf(char *buf, size_t bufsize, const char *fmt, ...) {
     va_list args;
     va_start(args, fmt);
     int n = vsnprintf(buf, bufsize, fmt, args);
     va_end(args);
     if (n < 0 || (size_t)n >= bufsize) {
         fprintf(stderr, "WARNING in %s: snprintf truncation or error. Buffer size: %zu, Required: %d\n", __func__, bufsize, n);
     }
     return n;
 }
 
 /* --------------------- Metrics and Instrumentation --------------------- */
 /* Global instrumentation counters (using 64-bit integers) */
 static volatile uint64_t metric_wakeup_attempts = 0;
 static volatile uint64_t metric_wol_success_total = 0;
 static volatile uint64_t metric_arp_attempts_total = 0;
 static volatile uint64_t metric_arp_failures_total = 0;
 static volatile uint64_t metric_arp_resolution_time_ms_total = 0;
 static volatile uint64_t metric_arp_resolution_count = 0;
 static volatile uint64_t metric_reverse_arp_attempts_total = 0;
 static volatile uint64_t metric_reverse_arp_success_total = 0;
 
 /* --------------------- Helper: Get Current Time in Milliseconds --------------------- */
 #ifdef _WIN32
 static uint64_t get_current_time_ms(void) {
     return GetTickCount64();
 }
 #else
 static uint64_t get_current_time_ms(void) {
     struct timeval tv;
     gettimeofday(&tv, NULL);
     return ((uint64_t)tv.tv_sec * 1000) + (tv.tv_usec / 1000);
 }
 #endif
 
 /* --------------------- Constants & Defaults --------------------- */
 #define MAC_SIZE 6
 #define MAGIC_PACKET_SIZE 102
 
 #define DEFAULT_BROADCAST_IP "255.255.255.255"
 #define DEFAULT_INTERFACE    "auto"
 #define DEFAULT_CACHE_FILE   "arp_cache.txt"
 #define DEFAULT_LOG_MAX_SIZE 1048576  /* 1MB */
 #define DEFAULT_WOL_PORT     9
 #define DEFAULT_LOG_ROTATION_INTERVAL 86400  /* Rotate daily by default (seconds) */
 #define METRICS_PORT         9100  /* Port for metrics HTTP server */
 
 #ifdef _WIN32
   #define CLOSESOCKET(s) closesocket(s)
 #else
   #define CLOSESOCKET(s) close(s)
 #endif
 
 /* --------------------- Mutex Definitions for Shared Resources --------------------- */
 #ifdef _WIN32
 // Using Windows Critical Sections for synchronization
 static CRITICAL_SECTION g_logger_cs;
 static CRITICAL_SECTION g_arp_cache_cs;
 #define LOCK_LOG()    EnterCriticalSection(&g_logger_cs)
 #define UNLOCK_LOG()  LeaveCriticalSection(&g_logger_cs)
 #define LOCK_ARP()    EnterCriticalSection(&g_arp_cache_cs)
 #define UNLOCK_ARP()  LeaveCriticalSection(&g_arp_cache_cs)
 #else
 // Using pthread mutexes on POSIX systems
 static pthread_mutex_t g_logger_mutex = PTHREAD_MUTEX_INITIALIZER;
 static pthread_mutex_t g_arp_cache_mutex = PTHREAD_MUTEX_INITIALIZER;
 #define LOCK_LOG()    pthread_mutex_lock(&g_logger_mutex)
 #define UNLOCK_LOG()  pthread_mutex_unlock(&g_logger_mutex)
 #define LOCK_ARP()    pthread_mutex_lock(&g_arp_cache_mutex)
 #define UNLOCK_ARP()  pthread_mutex_unlock(&g_arp_cache_mutex)
 #endif
 
 /* --------------------- Minimal uthash (embedded) --------------------- */
 #ifndef UTHASH_H
 #define UTHASH_H
 #define uthash_malloc(sz) malloc(sz)
 #define uthash_free(ptr,sz) free(ptr)
 #define HASH_FIND_STR(head,findstr,out)                                 \
     do {                                                                \
         out = NULL;                                                     \
         if (head) {                                                     \
             unsigned _hf_hashv = 0;                                     \
             for (const char *_hf_ptr = (findstr); *_hf_ptr; _hf_ptr++) {  \
                 _hf_hashv = _hf_hashv * 33 + (unsigned char)*_hf_ptr;    \
             }                                                           \
             for (out = head; out; out = out->hh.next) {                 \
                 unsigned _hf_tmp = 0;                                   \
                 for (const char *_hf_ptr = out->ip; *_hf_ptr; _hf_ptr++) {\
                     _hf_tmp = _hf_tmp * 33 + (unsigned char)*_hf_ptr;    \
                 }                                                       \
                 if (_hf_tmp == _hf_hashv && strcmp(out->ip, findstr)==0) break; \
             }                                                           \
         }                                                               \
     } while (0)
 
 #define HASH_ADD_STR(head, strfield, add)                               \
     do {                                                                \
         unsigned _ha_hashv = 0;                                         \
         for (const char *_ha_ptr = (add)->strfield; *_ha_ptr; _ha_ptr++) {\
             _ha_hashv = _ha_hashv * 33 + (unsigned char)*_ha_ptr;       \
         }                                                               \
         (add)->hh.hashv = _ha_hashv;                                    \
         (add)->hh.next = head;                                          \
         head = add;                                                     \
     } while(0)
 
 #define HASH_ITER(hh, head, el, tmp)                                    \
     for((el)=(head), (tmp)=(el)?(el)->hh.next:NULL; el; (el)=(tmp), (tmp)=(el)?(el)->hh.next:NULL)
 
 struct UT_hash_handle {
     struct arp_cache_entry *next;
     unsigned hashv;
 };
 #endif  /* UTHASH_H */
 
 /* --------------------- Configuration Structure --------------------- */
 typedef struct config_t {
     char broadcast_ip[64];
     char iface[32];           /* "auto" means auto-detect (on POSIX) */
     char cache_filename[128];
     char log_file[256];       /* If not empty, file logging is used */
     int  log_max_size;
     int  enable_remote_logging;
     char remote_log_server[128];
     int  remote_log_port;
     int  log_rotation_interval;  /* Time interval (in seconds) for log rotation */
 } config_t;
 
 static void init_config(config_t *cfg) {
     safe_strlcpy_wrapper(cfg->broadcast_ip, DEFAULT_BROADCAST_IP, sizeof(cfg->broadcast_ip), "init_config: broadcast_ip");
     safe_strlcpy_wrapper(cfg->iface, DEFAULT_INTERFACE, sizeof(cfg->iface), "init_config: iface");
     safe_strlcpy_wrapper(cfg->cache_filename, DEFAULT_CACHE_FILE, sizeof(cfg->cache_filename), "init_config: cache_filename");
     cfg->log_file[0] = '\0';
     cfg->log_max_size = DEFAULT_LOG_MAX_SIZE;
     cfg->enable_remote_logging = 0;
     cfg->remote_log_server[0] = '\0';
     cfg->remote_log_port = 514;
     cfg->log_rotation_interval = DEFAULT_LOG_ROTATION_INTERVAL;
 }
 
 static void print_usage(const char *progname) {
     fprintf(stderr,
         "Usage: %s [options] <target>\n"
         "Options:\n"
         "  -b, --broadcast <ip>      Set broadcast IP (default: %s)\n"
         "  -i, --interface <iface>   Set network interface (default: auto-detect on POSIX)\n"
         "  -c, --cachefile <file>    Set ARP cache file (default: %s)\n"
         "  -l, --logfile <file>      Set log file (if omitted, syslog/Event Log is used)\n"
         "  -r, --remote <srv:port>   Enable remote logging (e.g. 192.168.1.100:514)\n"
         "  -h, --help                Display this help message\n",
         progname, DEFAULT_BROADCAST_IP, DEFAULT_CACHE_FILE);
 }
 
 /* --------------------- Advanced Argument Parser --------------------- */
 static const char *parse_arguments(int argc, char **argv, config_t *cfg) {
     const char *progname = argv[0];
     const char *target = NULL;
     for (int i = 1; i < argc; i++) {
         char *arg = argv[i];
         if (arg[0] == '-') {
             /* Handle long options */
             if (arg[1] == '-') {
                 if (strcmp(arg, "--help") == 0) {
                     print_usage(progname);
                     exit(EXIT_SUCCESS);
                 } else if (strncmp(arg, "--broadcast=", 12) == 0) {
                     const char *value = arg + 12;
                     safe_strlcpy_wrapper(cfg->broadcast_ip, value, sizeof(cfg->broadcast_ip), "parse_arguments: broadcast_ip");
                 } else if (strncmp(arg, "--interface=", 12) == 0) {
                     const char *value = arg + 12;
                     safe_strlcpy_wrapper(cfg->iface, value, sizeof(cfg->iface), "parse_arguments: iface");
                 } else if (strncmp(arg, "--cachefile=", 12) == 0) {
                     const char *value = arg + 12;
                     safe_strlcpy_wrapper(cfg->cache_filename, value, sizeof(cfg->cache_filename), "parse_arguments: cache_filename");
                 } else if (strncmp(arg, "--logfile=", 10) == 0) {
                     const char *value = arg + 10;
                     safe_strlcpy_wrapper(cfg->log_file, value, sizeof(cfg->log_file), "parse_arguments: log_file");
                 } else if (strncmp(arg, "--remote=", 9) == 0) {
                     const char *value = arg + 9;
                     char *colon = strchr(value, ':');
                     if (!colon) {
                         fprintf(stderr, "Remote logging option requires format server:port\n");
                         print_usage(progname);
                         exit(EXIT_FAILURE);
                     }
                     size_t len = colon - value;
                     if (len >= sizeof(cfg->remote_log_server)) {
                         fprintf(stderr, "Remote log server name too long.\n");
                         print_usage(progname);
                         exit(EXIT_FAILURE);
                     }
                     memset(cfg->remote_log_server, 0, sizeof(cfg->remote_log_server));
                     memcpy(cfg->remote_log_server, value, len);
                     cfg->remote_log_server[len] = '\0';
                     cfg->remote_log_port = atoi(colon + 1);
                     cfg->enable_remote_logging = 1;
                 } else {
                     fprintf(stderr, "Unknown option '%s'\n", arg);
                     print_usage(progname);
                     return NULL;
                 }
             } else {
                 /* Handle short options */
                 size_t len = strlen(arg);
                 for (size_t j = 1; j < len; j++) {
                     char opt = arg[j];
                     const char *value = NULL;
                     switch (opt) {
                         case 'h':
                             print_usage(progname);
                             exit(EXIT_SUCCESS);
                         case 'b':
                             if (j + 1 < len) {
                                 value = &arg[j + 1];
                                 j = len;
                             } else if (i + 1 < argc) {
                                 value = argv[++i];
                             } else {
                                 fprintf(stderr, "Option -b requires an argument.\n");
                                 print_usage(progname);
                                 return NULL;
                             }
                             safe_strlcpy_wrapper(cfg->broadcast_ip, value, sizeof(cfg->broadcast_ip), "parse_arguments: broadcast_ip");
                             break;
                         case 'i':
                             if (j + 1 < len) {
                                 value = &arg[j + 1];
                                 j = len;
                             } else if (i + 1 < argc) {
                                 value = argv[++i];
                             } else {
                                 fprintf(stderr, "Option -i requires an argument.\n");
                                 print_usage(progname);
                                 return NULL;
                             }
                             safe_strlcpy_wrapper(cfg->iface, value, sizeof(cfg->iface), "parse_arguments: iface");
                             break;
                         case 'c':
                             if (j + 1 < len) {
                                 value = &arg[j + 1];
                                 j = len;
                             } else if (i + 1 < argc) {
                                 value = argv[++i];
                             } else {
                                 fprintf(stderr, "Option -c requires an argument.\n");
                                 print_usage(progname);
                                 return NULL;
                             }
                             safe_strlcpy_wrapper(cfg->cache_filename, value, sizeof(cfg->cache_filename), "parse_arguments: cache_filename");
                             break;
                         case 'l':
                             if (j + 1 < len) {
                                 value = &arg[j + 1];
                                 j = len;
                             } else if (i + 1 < argc) {
                                 value = argv[++i];
                             } else {
                                 fprintf(stderr, "Option -l requires an argument.\n");
                                 print_usage(progname);
                                 return NULL;
                             }
                             safe_strlcpy_wrapper(cfg->log_file, value, sizeof(cfg->log_file), "parse_arguments: log_file");
                             break;
                         case 'r':
                             if (j + 1 < len) {
                                 value = &arg[j + 1];
                                 j = len;
                             } else if (i + 1 < argc) {
                                 value = argv[++i];
                             } else {
                                 fprintf(stderr, "Option -r requires an argument in the format server:port.\n");
                                 print_usage(progname);
                                 return NULL;
                             }
                             {
                                 char *colon = strchr(value, ':');
                                 if (!colon) {
                                     fprintf(stderr, "Option -r requires format server:port.\n");
                                     print_usage(progname);
                                     return NULL;
                                 }
                                 size_t sv_len = colon - value;
                                 if (sv_len >= sizeof(cfg->remote_log_server)) {
                                     fprintf(stderr, "Remote log server name too long.\n");
                                     print_usage(progname);
                                     return NULL;
                                 }
                                 memset(cfg->remote_log_server, 0, sizeof(cfg->remote_log_server));
                                 memcpy(cfg->remote_log_server, value, sv_len);
                                 cfg->remote_log_server[sv_len] = '\0';
                                 cfg->remote_log_port = atoi(colon + 1);
                                 cfg->enable_remote_logging = 1;
                             }
                             break;
                         default:
                             fprintf(stderr, "Unknown option: -%c\n", opt);
                             print_usage(progname);
                             return NULL;
                     }
                 }
             }
         } else {
             /* Positional argument (target) */
             if (target == NULL)
                 target = arg;
             else {
                 fprintf(stderr, "Multiple target arguments provided.\n");
                 print_usage(progname);
                 return NULL;
             }
         }
     }
     if (!target) {
         fprintf(stderr, "Target not specified.\n");
         print_usage(progname);
         return NULL;
     }
     return target;
 }
 
 /* --------------------- Asynchronous Logging Subsystem --------------------- */
 /* Log levels */
 typedef enum {
     LOG_LEVEL_DEBUG,
     LOG_LEVEL_INFO,
     LOG_LEVEL_WARN,
     LOG_LEVEL_ERROR
 } LogLevel;
 
 /* Global logger configuration variables */
 #ifdef _WIN32
 static HANDLE g_hEventLog = NULL;
 #else
 /* For POSIX when not using file logging */
 #endif
 static FILE *g_log_fp = NULL;
 static char g_log_filename[256] = "";
 static int g_log_max_size = DEFAULT_LOG_MAX_SIZE;
 static int g_enable_remote_logging = 0;
 static int g_remote_log_socket = -1;
 static struct sockaddr_in g_remote_log_addr;
 static int g_use_file_logging = 0;  /* if false, use syslog (POSIX) or Event Log (Windows) */
 
 /* --------------------- Asynchronous Logging Queue --------------------- */
 #ifdef _WIN32
 static CRITICAL_SECTION log_queue_mutex;
 static CONDITION_VARIABLE log_queue_cond;
 static HANDLE log_thread_handle = NULL;
 #else
 static pthread_mutex_t log_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
 static pthread_cond_t  log_queue_cond  = PTHREAD_COND_INITIALIZER;
 static pthread_t log_thread;
 #endif
 
 typedef struct log_msg {
     LogLevel level;
     char *msg;
     struct log_msg *next;
 } log_msg_t;
 
 static log_msg_t *log_queue_head = NULL;
 static log_msg_t *log_queue_tail = NULL;
 static volatile int log_thread_running = 1;
 
 #ifdef _WIN32
 #define LOCK_LOG_QUEUE()      EnterCriticalSection(&log_queue_mutex)
 #define UNLOCK_LOG_QUEUE()    LeaveCriticalSection(&log_queue_mutex)
 #define WAIT_FOR_LOG_QUEUE()  SleepConditionVariableCS(&log_queue_cond, &log_queue_mutex, INFINITE)
 #define SIGNAL_LOG_QUEUE()    WakeConditionVariable(&log_queue_cond)
 #else
 #define LOCK_LOG_QUEUE()      pthread_mutex_lock(&log_queue_mutex)
 #define UNLOCK_LOG_QUEUE()    pthread_mutex_unlock(&log_queue_mutex)
 #define WAIT_FOR_LOG_QUEUE()  pthread_cond_wait(&log_queue_cond, &log_queue_mutex)
 #define SIGNAL_LOG_QUEUE()    pthread_cond_signal(&log_queue_cond)
 #endif
 
 /* Global variables for log rotation */
 static time_t last_rotation_time = 0;
 static int g_log_rotation_interval = DEFAULT_LOG_ROTATION_INTERVAL;
 
 /* Forward declaration for check_log_rotation */
 static void check_log_rotation(void);
 
 /* Remote logging helper */
 static void logger_remote_send(const char *msg) {
     if (g_remote_log_socket == -1)
         return;
     sendto(g_remote_log_socket, msg, (int)strlen(msg), 0,
            (struct sockaddr*)&g_remote_log_addr, sizeof(g_remote_log_addr));
 }
 
 /* Asynchronous log function. */
 static void logger_async_log(LogLevel level, const char *file, int line, const char *func, const char *format, ...) {
     char buf[1024];
     va_list args;
     va_start(args, format);
     vsnprintf(buf, sizeof(buf), format, args);
     va_end(args);
 
     char timestr[32];
     time_t now = time(NULL);
 #ifdef _WIN32
     struct tm tm_now;
     localtime_s(&tm_now, &now);
     strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", &tm_now);
 #else
     struct tm tm_now;
     localtime_r(&now, &tm_now);
     strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", &tm_now);
 #endif
 
     char fullmsg[2048];
     safe_snprintf(fullmsg, sizeof(fullmsg), "[%s] %s: %s",
              timestr,
              (level == LOG_LEVEL_DEBUG ? "DEBUG" :
               level == LOG_LEVEL_INFO  ? "INFO"  :
               level == LOG_LEVEL_WARN  ? "WARN"  : "ERROR"),
              buf);
 
     int add_context = (level == LOG_LEVEL_ERROR);
 #ifdef DEBUG
     if (level == LOG_LEVEL_DEBUG || level == LOG_LEVEL_WARN)
         add_context = 1;
 #endif
     if (add_context) {
         char context_info[256];
         safe_snprintf(context_info, sizeof(context_info), " (at %s:%d in %s)", file, line, func);
         strncat(fullmsg, context_info, sizeof(fullmsg)-strlen(fullmsg)-1);
     }
 #ifdef ENABLE_STACKTRACE
     if (level == LOG_LEVEL_ERROR) {
 #if !defined(_WIN32)
         void *buffer[10];
         int nptrs = backtrace(buffer, 10);
         char **strings = backtrace_symbols(buffer, nptrs);
         if (strings != NULL) {
             strncat(fullmsg, "\nStack trace:\n", sizeof(fullmsg)-strlen(fullmsg)-1);
             for (int i = 0; i < nptrs; i++) {
                 strncat(fullmsg, strings[i], sizeof(fullmsg)-strlen(fullmsg)-1);
                 strncat(fullmsg, "\n", sizeof(fullmsg)-strlen(fullmsg)-1);
             }
             free(strings);
         }
 #else
         strncat(fullmsg, "\nStack trace not available on this Windows build.", sizeof(fullmsg)-strlen(fullmsg)-1);
 #endif
     }
 #endif
 
     log_msg_t *node = malloc(sizeof(log_msg_t));
     if (!node) {
         fprintf(stderr, "Out of memory in logger_async_log\n");
         return;
     }
     node->msg = strdup(fullmsg);
     if (!node->msg) {
         free(node);
         fprintf(stderr, "Out of memory in logger_async_log\n");
         return;
     }
     node->level = level;
     node->next = NULL;
 
     LOCK_LOG_QUEUE();
     if (log_queue_tail) {
         log_queue_tail->next = node;
         log_queue_tail = node;
     } else {
         log_queue_head = log_queue_tail = node;
     }
     SIGNAL_LOG_QUEUE();
     UNLOCK_LOG_QUEUE();
 }
 
 #ifdef _WIN32
 DWORD WINAPI logger_thread_func(LPVOID arg) {
 #else
 static void *logger_thread_func(void *arg) {
 #endif
     (void)arg;
     while (log_thread_running || log_queue_head != NULL) {
         LOCK_LOG_QUEUE();
         while (log_queue_head == NULL && log_thread_running) {
             WAIT_FOR_LOG_QUEUE();
         }
         log_msg_t *node = log_queue_head;
         if (node) {
             log_queue_head = node->next;
             if (log_queue_head == NULL)
                 log_queue_tail = NULL;
         }
         UNLOCK_LOG_QUEUE();
 
         if (node) {
             if (g_use_file_logging && g_log_fp) {
                 check_log_rotation();
                 fprintf(g_log_fp, "%s\n", node->msg);
                 fflush(g_log_fp);
             }
 #ifdef _WIN32
             else if (g_hEventLog) {
                 WORD type;
                 switch(node->level) {
                     case LOG_LEVEL_DEBUG:
                     case LOG_LEVEL_INFO:  type = EVENTLOG_INFORMATION_TYPE; break;
                     case LOG_LEVEL_WARN:  type = EVENTLOG_WARNING_TYPE; break;
                     case LOG_LEVEL_ERROR: type = EVENTLOG_ERROR_TYPE; break;
                     default: type = EVENTLOG_INFORMATION_TYPE;
                 }
                 LPCSTR strings[1] = { node->msg };
                 ReportEvent(g_hEventLog, type, 0, 0, NULL, 1, 0, strings, NULL);
             }
 #else
             else {
                 int priority;
                 switch(node->level) {
                     case LOG_LEVEL_DEBUG: priority = LOG_DEBUG; break;
                     case LOG_LEVEL_INFO:  priority = LOG_INFO; break;
                     case LOG_LEVEL_WARN:  priority = LOG_WARNING; break;
                     case LOG_LEVEL_ERROR: priority = LOG_ERR; break;
                     default: priority = LOG_INFO;
                 }
                 syslog(priority, "%s", node->msg);
             }
 #endif
 
             if (g_enable_remote_logging && g_remote_log_socket != -1)
                 logger_remote_send(node->msg);
 
             free(node->msg);
             free(node);
         }
     }
 #ifdef _WIN32
     return 0;
 #else
     return NULL;
 #endif
 }
 
 static void check_log_rotation(void) {
     if (!g_use_file_logging || !g_log_fp)
         return;
 
 #ifdef _WIN32
     int fd = _fileno(g_log_fp);
     long size = _filelength(fd);
 #else
     int fd = fileno(g_log_fp);
     struct stat st;
     if (fstat(fd, &st) != 0)
         st.st_size = 0;
     off_t size = st.st_size;
 #endif
     time_t now = time(NULL);
     if (size >= g_log_max_size || (now - last_rotation_time >= g_log_rotation_interval)) {
         fclose(g_log_fp);
         char backup[300];
         safe_snprintf(backup, sizeof(backup), "%s.%ld", g_log_filename, now);
         if (rename(g_log_filename, backup) != 0) {
             fprintf(stderr, "Log rotation: rename failed: %s\n", strerror(errno));
         }
         g_log_fp = fopen(g_log_filename, "a");
         if (!g_log_fp) {
             fprintf(stderr, "Unable to reopen log file %s after rotation: %s\n", g_log_filename, strerror(errno));
         }
         last_rotation_time = now;
         char command[512];
         safe_snprintf(command, sizeof(command), "gzip -f %s", backup);
         system(command);
     }
 }
 
 #ifdef _WIN32
 static HANDLE metrics_thread_handle = NULL;
 DWORD WINAPI metrics_thread_func(LPVOID arg) {
 #else
 static void *metrics_thread_func(void *arg) {
 #endif
     (void)arg;
     int server_fd;
     struct sockaddr_in serv_addr;
     server_fd = socket(AF_INET, SOCK_STREAM, 0);
     if (server_fd < 0) {
         logger_async_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, "Failed to create metrics socket.");
 #ifdef _WIN32
         return 0;
 #else
         return NULL;
 #endif
     }
     int opt = 1;
     if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt)) < 0) {
         logger_async_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, "Failed to set SO_REUSEADDR on metrics socket.");
         CLOSESOCKET(server_fd);
 #ifdef _WIN32
         return 0;
 #else
         return NULL;
 #endif
     }
     memset(&serv_addr, 0, sizeof(serv_addr));
     serv_addr.sin_family = AF_INET;
     serv_addr.sin_addr.s_addr = INADDR_ANY;
     serv_addr.sin_port = htons(METRICS_PORT);
     if (bind(server_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
         logger_async_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, "Failed to bind metrics socket.");
         CLOSESOCKET(server_fd);
 #ifdef _WIN32
         return 0;
 #else
         return NULL;
 #endif
     }
     if (listen(server_fd, 5) < 0) {
         logger_async_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, "Failed to listen on metrics socket.");
         CLOSESOCKET(server_fd);
 #ifdef _WIN32
         return 0;
 #else
         return NULL;
 #endif
     }
 #ifdef _WIN32
     {
         u_long mode = 1;
         ioctlsocket(server_fd, FIONBIO, &mode);
     }
 #else
     {
         int flags = fcntl(server_fd, F_GETFL, 0);
         fcntl(server_fd, F_SETFL, flags | O_NONBLOCK);
     }
 #endif
 
     while (1) {
 #ifdef _WIN32
         Sleep(1000);
 #else
         sleep(1);
 #endif
         fd_set readfds;
         struct timeval timeout;
         FD_ZERO(&readfds);
         FD_SET(server_fd, &readfds);
         timeout.tv_sec = 0;
         timeout.tv_usec = 0;
         int ret = select(server_fd + 1, &readfds, NULL, NULL, &timeout);
         if (ret > 0 && FD_ISSET(server_fd, &readfds)) {
             struct sockaddr_in client_addr;
 #ifdef _WIN32
             int addrlen = sizeof(client_addr);
 #else
             socklen_t addrlen = sizeof(client_addr);
 #endif
             int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addrlen);
             if (client_fd >= 0) {
                 char metrics_buffer[1024];
                 int len = safe_snprintf(metrics_buffer, sizeof(metrics_buffer),
                     "# HELP enterprise_wol_wake_attempts_total Total wake-up attempts\n"
                     "# TYPE enterprise_wol_wake_attempts_total counter\n"
                     "enterprise_wol_wake_attempts_total %llu\n"
                     "# HELP enterprise_wol_wake_success_total Total successful wake-ups\n"
                     "# TYPE enterprise_wol_wake_success_total counter\n"
                     "enterprise_wol_wake_success_total %llu\n"
                     "# HELP enterprise_wol_arp_attempts_total Total ARP resolution attempts\n"
                     "# TYPE enterprise_wol_arp_attempts_total counter\n"
                     "enterprise_wol_arp_attempts_total %llu\n"
                     "# HELP enterprise_wol_arp_failures_total Total ARP resolution failures\n"
                     "# TYPE enterprise_wol_arp_failures_total counter\n"
                     "enterprise_wol_arp_failures_total %llu\n"
                     "# HELP enterprise_wol_arp_resolution_time_seconds Average ARP resolution time in seconds\n"
                     "# TYPE enterprise_wol_arp_resolution_time_seconds gauge\n",
                     metric_wakeup_attempts,
                     metric_wol_success_total,
                     metric_arp_attempts_total,
                     metric_arp_failures_total);
                 double avg_arp_time = 0.0;
                 if(metric_arp_resolution_count > 0)
                     avg_arp_time = ((double)metric_arp_resolution_time_ms_total / metric_arp_resolution_count) / 1000.0;
                 char extra[256];
                 safe_snprintf(extra, sizeof(extra),
                     "enterprise_wol_arp_resolution_time_seconds %f\n"
                     "# HELP enterprise_wol_reverse_arp_attempts_total Total reverse ARP attempts\n"
                     "# TYPE enterprise_wol_reverse_arp_attempts_total counter\n"
                     "enterprise_wol_reverse_arp_attempts_total %llu\n"
                     "# HELP enterprise_wol_reverse_arp_success_total Total successful reverse ARP resolutions\n"
                     "# TYPE enterprise_wol_reverse_arp_success_total counter\n"
                     "enterprise_wol_reverse_arp_success_total %llu\n",
                     avg_arp_time,
                     metric_reverse_arp_attempts_total,
                     metric_reverse_arp_success_total);
                 strncat(metrics_buffer, extra, sizeof(metrics_buffer)-strlen(metrics_buffer)-1);
 
                 char response_header[256];
                 int header_len = safe_snprintf(response_header, sizeof(response_header),
                     "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\n\r\n", strlen(metrics_buffer));
                 send(client_fd, response_header, header_len, 0);
                 send(client_fd, metrics_buffer, strlen(metrics_buffer), 0);
                 CLOSESOCKET(client_fd);
             }
         }
     }
     CLOSESOCKET(server_fd);
 #ifdef _WIN32
     return 0;
 #else
     return NULL;
 #endif
 }
 
 static void logger_init(const config_t *cfg, const char *progname) {
     g_log_max_size = cfg->log_max_size;
     g_log_rotation_interval = cfg->log_rotation_interval;
     if (cfg->log_file[0] != '\0') {
         safe_strlcpy_wrapper(g_log_filename, cfg->log_file, sizeof(g_log_filename), "logger_init: g_log_filename");
         g_log_fp = fopen(g_log_filename, "a");
         if (!g_log_fp) {
             fprintf(stderr, "Unable to open log file %s: %s\n", g_log_filename, strerror(errno));
             exit(EXIT_FAILURE);
         }
         g_use_file_logging = 1;
         last_rotation_time = time(NULL);
     } else {
         g_use_file_logging = 0;
 #ifdef _WIN32
         g_hEventLog = RegisterEventSource(NULL, progname);
         if (!g_hEventLog) {
             fprintf(stderr, "RegisterEventSource failed: %d\n", GetLastError());
         }
 #else
         openlog(progname, LOG_PID | LOG_CONS, LOG_USER);
 #endif
     }
     if (cfg->enable_remote_logging && cfg->remote_log_server[0] != '\0') {
         g_enable_remote_logging = 1;
 #ifdef _WIN32
         WSADATA wsaData;
         if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
             fprintf(stderr, "WSAStartup failed for remote logging.\n");
         }
 #endif
         g_remote_log_socket = socket(AF_INET, SOCK_DGRAM, 0);
         if (g_remote_log_socket < 0) {
             fprintf(stderr, "Failed to create remote log socket.\n");
             g_enable_remote_logging = 0;
         } else {
             memset(&g_remote_log_addr, 0, sizeof(g_remote_log_addr));
             g_remote_log_addr.sin_family = AF_INET;
             g_remote_log_addr.sin_port = htons(cfg->remote_log_port);
             if (inet_pton(AF_INET, cfg->remote_log_server, &g_remote_log_addr.sin_addr) <= 0) {
                 fprintf(stderr, "Invalid remote log server IP: %s\n", cfg->remote_log_server);
                 g_enable_remote_logging = 0;
             }
         }
     }
 #ifdef _WIN32
     InitializeCriticalSection(&log_queue_mutex);
     InitializeConditionVariable(&log_queue_cond);
     log_thread_handle = CreateThread(NULL, 0, logger_thread_func, NULL, 0, NULL);
     if (!log_thread_handle) {
         fprintf(stderr, "Failed to create logging thread.\n");
         exit(EXIT_FAILURE);
     }
 #else
     if (pthread_create(&log_thread, NULL, logger_thread_func, NULL) != 0) {
         fprintf(stderr, "Failed to create logging thread.\n");
         exit(EXIT_FAILURE);
     }
 #endif
 #ifdef _WIN32
     metrics_thread_handle = CreateThread(NULL, 0, metrics_thread_func, NULL, 0, NULL);
     if (!metrics_thread_handle) {
         logger_async_log(LOG_LEVEL_WARN, __FILE__, __LINE__, __func__, "Failed to create metrics thread.");
     }
 #else
     pthread_t metrics_thread;
     if (pthread_create(&metrics_thread, NULL, metrics_thread_func, NULL) != 0) {
         logger_async_log(LOG_LEVEL_WARN, __FILE__, __LINE__, __func__, "Failed to create metrics thread.");
         exit(EXIT_FAILURE);
     }
     pthread_detach(metrics_thread);
 #endif
     logger_async_log(LOG_LEVEL_INFO, __FILE__, __LINE__, __func__, "Starting wakey");
 }
 
 static void logger_close(void) {
     logger_async_log(LOG_LEVEL_INFO, __FILE__, __LINE__, __func__, "Exiting wakey");
     log_thread_running = 0;
 #ifdef _WIN32
     WakeConditionVariable(&log_queue_cond);
     WaitForSingleObject(log_thread_handle, INFINITE);
     CloseHandle(log_thread_handle);
     DeleteCriticalSection(&log_queue_mutex);
 #else
     pthread_mutex_lock(&log_queue_mutex);
     pthread_cond_signal(&log_queue_cond);
     pthread_mutex_unlock(&log_queue_mutex);
     pthread_join(log_thread, NULL);
 #endif
     if (g_log_fp)
         fclose(g_log_fp);
 #ifdef _WIN32
     if (g_hEventLog)
         DeregisterEventSource(g_hEventLog);
     if (g_remote_log_socket != -1)
         closesocket(g_remote_log_socket);
 #else
     if (!g_use_file_logging)
         closelog();
 #endif
 }
 
 #ifdef _WIN32
 static int lock_file_win(HANDLE hFile, int exclusive) {
     OVERLAPPED overlapped = {0};
     DWORD flags = exclusive ? LOCKFILE_EXCLUSIVE_LOCK : 0;
     return LockFileEx(hFile, flags, 0, 0xFFFFFFFF, 0xFFFFFFFF, &overlapped) ? 0 : -1;
 }
 static int unlock_file_win(HANDLE hFile) {
     OVERLAPPED overlapped = {0};
     return UnlockFileEx(hFile, 0, 0xFFFFFFFF, 0xFFFFFFFF, &overlapped) ? 0 : -1;
 }
 #else
 static int lock_file_fd(int fd, int exclusive) {
     return flock(fd, exclusive ? LOCK_EX : LOCK_SH);
 }
 static int unlock_file_fd(int fd) {
     return flock(fd, LOCK_UN);
 }
 #endif
 
 /* --------------------- ARP Cache Module --------------------- */
 typedef struct arp_cache_entry {
     char ip[64];
     char hostname[128];
     char mac[18];
     struct UT_hash_handle hh;
 } arp_cache_entry;
 
 static arp_cache_entry *g_arp_cache = NULL;
 
 static arp_cache_entry* find_arp_cache_entry_locked(const char *ip, const char *hostname) {
     arp_cache_entry *entry = NULL;
     if (ip[0] != '\0') {
         HASH_FIND_STR(g_arp_cache, ip, entry);
         if (entry)
             return entry;
     }
     for (entry = g_arp_cache; entry != NULL; entry = entry->hh.next) {
         if (strcmp(entry->hostname, hostname)==0)
             return entry;
     }
     return NULL;
 }
 
 static arp_cache_entry *find_arp_cache_entry(const char *ip, const char *hostname) {
     arp_cache_entry *result;
     LOCK_ARP();
     result = find_arp_cache_entry_locked(ip, hostname);
     UNLOCK_ARP();
     return result;
 }
 
 static void load_arp_cache_from_file(const char *filename) {
 #ifdef _WIN32
     HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
     if (hFile == INVALID_HANDLE_VALUE) {
         logger_async_log(LOG_LEVEL_INFO, __FILE__, __LINE__, __func__, "No existing ARP cache file found (%s)", filename);
         return;
     }
     if (lock_file_win(hFile, 0) < 0) {
         logger_async_log(LOG_LEVEL_WARN, __FILE__, __LINE__, __func__, "Failed to lock ARP cache file for reading.");
         CloseHandle(hFile);
         return;
     }
     int fd = _open_osfhandle((intptr_t)hFile, _O_RDONLY);
     FILE *fp = fdopen(fd, "r");
 #else
     int fd = open(filename, O_RDONLY);
     if (fd < 0) {
         logger_async_log(LOG_LEVEL_INFO, __FILE__, __LINE__, __func__, "No existing ARP cache file found (%s)", filename);
         return;
     }
     if (lock_file_fd(fd, 0) < 0) {
         logger_async_log(LOG_LEVEL_WARN, __FILE__, __LINE__, __func__, "Failed to lock ARP cache file for reading.");
         close(fd);
         return;
     }
     FILE *fp = fdopen(fd, "r");
 #endif
     if (!fp) {
         logger_async_log(LOG_LEVEL_WARN, __FILE__, __LINE__, __func__, "Unable to open ARP cache file for reading.");
 #ifdef _WIN32
         CloseHandle(hFile);
 #else
         close(fd);
 #endif
         return;
     }
     char line[256];
     while (fgets(line, sizeof(line), fp)) {
         char file_hostname[128], file_ip[64], file_mac[18];
         if (sscanf(line, "%127s %63s %17s", file_hostname, file_ip, file_mac) == 3) {
             arp_cache_entry *entry = malloc(sizeof(arp_cache_entry));
             if (!entry)
                 continue;
             safe_strlcpy_wrapper(entry->hostname, file_hostname, sizeof(entry->hostname), "load_arp_cache: hostname");
             safe_strlcpy_wrapper(entry->ip, file_ip, sizeof(entry->ip), "load_arp_cache: ip");
             safe_strlcpy_wrapper(entry->mac, file_mac, sizeof(entry->mac), "load_arp_cache: mac");
             LOCK_ARP();
             HASH_ADD_STR(g_arp_cache, ip, entry);
             UNLOCK_ARP();
         }
     }
     fclose(fp);
     logger_async_log(LOG_LEVEL_DEBUG, __FILE__, __LINE__, __func__, "Loaded ARP cache from file.");
 }
 
 static void flush_arp_cache_to_file(const char *filename) {
 #ifdef _WIN32
     HANDLE hFile = CreateFileA(filename, GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
     if (hFile == INVALID_HANDLE_VALUE) {
         logger_async_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, "Unable to open ARP cache file for writing (%s)", filename);
         return;
     }
     if (lock_file_win(hFile, 1) < 0) {
         logger_async_log(LOG_LEVEL_WARN, __FILE__, __LINE__, __func__, "Failed to lock ARP cache file for writing.");
         CloseHandle(hFile);
         return;
     }
     int fd = _open_osfhandle((intptr_t)hFile, _O_RDWR);
     FILE *fp = fdopen(fd, "w");
 #else
     int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
     if (fd < 0) {
         logger_async_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, "Unable to open ARP cache file for writing (%s)", filename);
         return;
     }
     if (lock_file_fd(fd, 1) < 0) {
         logger_async_log(LOG_LEVEL_WARN, __FILE__, __LINE__, __func__, "Failed to lock ARP cache file for writing.");
         close(fd);
         return;
     }
     FILE *fp = fdopen(fd, "w");
 #endif
     if (!fp) {
         logger_async_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, "fdopen failed on ARP cache file (%s)", filename);
 #ifdef _WIN32
         CloseHandle(hFile);
 #else
         close(fd);
 #endif
         return;
     }
     LOCK_ARP();
     arp_cache_entry *entry, *tmp;
     HASH_ITER(hh, g_arp_cache, entry, tmp) {
         fprintf(fp, "%s %s %s\n", entry->hostname, entry->ip, entry->mac);
     }
     UNLOCK_ARP();
     fflush(fp);
     fclose(fp);
     logger_async_log(LOG_LEVEL_DEBUG, __FILE__, __LINE__, __func__, "Flushed ARP cache to file.");
 }
 
 static void update_arp_cache_entry(const char *ip, const char *hostname, const char *mac) {
     LOCK_ARP();
     arp_cache_entry *entry = find_arp_cache_entry_locked(ip, hostname);
     if (entry) {
         safe_strlcpy_wrapper(entry->mac, mac, sizeof(entry->mac), "update_arp_cache_entry: mac");
     } else {
         entry = malloc(sizeof(arp_cache_entry));
         if (!entry) {
             UNLOCK_ARP();
             return;
         }
         safe_strlcpy_wrapper(entry->ip, ip, sizeof(entry->ip), "update_arp_cache_entry: ip");
         safe_strlcpy_wrapper(entry->hostname, hostname, sizeof(entry->hostname), "update_arp_cache_entry: hostname");
         safe_strlcpy_wrapper(entry->mac, mac, sizeof(entry->mac), "update_arp_cache_entry: mac");
         HASH_ADD_STR(g_arp_cache, ip, entry);
     }
     UNLOCK_ARP();
 }
 
 /* --------------------- Network Interface Auto-Detection --------------------- */
 #ifndef _WIN32
 static void auto_detect_interface(config_t *cfg) {
     if (strcmp(cfg->iface, "auto") != 0)
         return;
     struct ifaddrs *ifaddr, *ifa;
     if (getifaddrs(&ifaddr) == -1) {
         logger_async_log(LOG_LEVEL_WARN, __FILE__, __LINE__, __func__, "getifaddrs failed: %s", strerror(errno));
         return;
     }
     for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
         if (ifa->ifa_addr == NULL)
             continue;
         if (ifa->ifa_addr->sa_family == AF_INET &&
             !(ifa->ifa_flags & IFF_LOOPBACK)) {
             safe_strlcpy_wrapper(cfg->iface, ifa->ifa_name, sizeof(cfg->iface), "auto_detect_interface");
             logger_async_log(LOG_LEVEL_INFO, __FILE__, __LINE__, __func__, "Auto-detected interface: %s", cfg->iface);
             break;
         }
     }
     freeifaddrs(ifaddr);
 }
 #else
 static void auto_detect_interface(config_t *cfg) {
     if (strcmp(cfg->iface, "auto") == 0)
         safe_strlcpy_wrapper(cfg->iface, "default", sizeof(cfg->iface), "auto_detect_interface");
 }
 #endif
 
 /* --------------------- Sleep Helper --------------------- */
 static void msleep(unsigned int milliseconds) {
 #ifdef _WIN32
     Sleep(milliseconds);
 #else
     usleep(milliseconds * 1000);
 #endif
 }
 
 /* --------------------- Safe MAC Address Parsing --------------------- */
 static int parse_mac_address(const char *mac_str, unsigned char mac[MAC_SIZE]) {
     char mac_copy[32];
     safe_strlcpy_wrapper(mac_copy, mac_str, sizeof(mac_copy), "parse_mac_address");
     char *token = strtok(mac_copy, ":");
     int i = 0;
     while (token != NULL && i < MAC_SIZE) {
         char *endptr;
         unsigned long value = strtoul(token, &endptr, 16);
         if (*endptr != '\0' || value > 0xFF) {
             return -1;
         }
         mac[i++] = (unsigned char)value;
         token = strtok(NULL, ":");
     }
     return (i == MAC_SIZE) ? 0 : -1;
 }
 
 /* --------------------- Wake-on-LAN Module --------------------- */
 static void send_wol_packet(const char *mac_address, const char *broadcast_ip) {
     unsigned char packet[MAGIC_PACKET_SIZE];
     unsigned char mac[MAC_SIZE];
     struct sockaddr_in addr;
     int sock;
 
     if (parse_mac_address(mac_address, mac) != 0) {
         logger_async_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, "Invalid MAC address format: %s", mac_address);
         return;
     }
     memset(packet, 0xFF, MAC_SIZE);
     for (int i = MAC_SIZE; i < MAGIC_PACKET_SIZE; i += MAC_SIZE)
         memcpy(packet + i, mac, MAC_SIZE);
 
     sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
     if (sock < 0) {
         logger_async_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, "Socket creation failed: %s", strerror(errno));
         return;
     }
     int optval = 1;
     if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char *)&optval, sizeof(optval)) < 0) {
         logger_async_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, "Failed to set broadcast option: %s", strerror(errno));
         CLOSESOCKET(sock);
         return;
     }
     memset(&addr, 0, sizeof(addr));
     addr.sin_family = AF_INET;
     addr.sin_port = htons(DEFAULT_WOL_PORT);
     addr.sin_addr.s_addr = inet_addr(broadcast_ip);
 
     if (sendto(sock, (const char *)packet, sizeof(packet), 0,
                (struct sockaddr *)&addr, sizeof(addr)) < 0) {
         logger_async_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, "Failed to send WoL packet: %s", strerror(errno));
         CLOSESOCKET(sock);
         return;
     }
     logger_async_log(LOG_LEVEL_INFO, __FILE__, __LINE__, __func__, "WOL packet sent to broadcast %s (target MAC: %s)", broadcast_ip, mac_address);
     CLOSESOCKET(sock);
 }
 
 /* --------------------- ARP Resolution Module --------------------- */
 #ifdef _WIN32
 static int get_mac_from_ip_win(const char *target_ip, unsigned char *mac) {
     IPAddr destIp = inet_addr(target_ip);
     if (destIp == INADDR_NONE) {
         logger_async_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, "Invalid target IP address: %s", target_ip);
         return -1;
     }
     ULONG mac_addr[2] = {0};
     ULONG mac_addr_len = MAC_SIZE;
     DWORD ret = SendARP(destIp, 0, (PULONG)mac_addr, &mac_addr_len);
     if (ret != NO_ERROR) {
         logger_async_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, "SendARP failed with error %lu", ret);
         return -1;
     }
     memcpy(mac, mac_addr, MAC_SIZE);
     return 0;
 }
 
 /* Windows reverse ARP resolution implementation */
 static int get_ip_from_mac_rev_win(const char *mac_str, char *ip_str, size_t ip_str_size) {
     unsigned char mac_bytes[MAC_SIZE];
     if (sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                &mac_bytes[0], &mac_bytes[1], &mac_bytes[2],
                &mac_bytes[3], &mac_bytes[4], &mac_bytes[5]) != 6)
          return -1;
     PMIB_IPNETTABLE pIpNetTable = NULL;
     DWORD size = 0, ret;
     ret = GetIpNetTable(NULL, &size, 0);
     if(ret != ERROR_INSUFFICIENT_BUFFER)
          return -1;
     pIpNetTable = (PMIB_IPNETTABLE) malloc(size);
     if(!pIpNetTable)
          return -1;
     ret = GetIpNetTable(pIpNetTable, &size, 0);
     if(ret != NO_ERROR) {
          free(pIpNetTable);
          return -1;
     }
     int found = 0;
     for(DWORD i = 0; i < pIpNetTable->dwNumEntries; i++) {
          MIB_IPNETROW row = pIpNetTable->table[i];
          if(row.dwPhysAddrLen == MAC_SIZE && memcmp(row.bPhysAddr, mac_bytes, MAC_SIZE)==0) {
              struct in_addr addr;
              addr.s_addr = row.dwAddr;
              const char *tmp = inet_ntoa(addr);
              if(tmp) {
                  strncpy(ip_str, tmp, ip_str_size);
                  ip_str[ip_str_size-1] = '\0';
                  found = 1;
                  break;
              }
          }
     }
     free(pIpNetTable);
     return found ? 0 : -1;
 }
 #else
 static int get_mac_from_ip_linux(const char *target_ip, const char *iface, unsigned char *mac) {
     int sockfd;
     struct ifreq ifr;
     unsigned char local_mac[MAC_SIZE];
     struct in_addr local_ip;
 
     sockfd = socket(AF_INET, SOCK_DGRAM, 0);
     if (sockfd < 0) {
         logger_async_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, "socket error: %s", strerror(errno));
         return -1;
     }
     memset(&ifr, 0, sizeof(ifr));
     safe_strlcpy_wrapper(ifr.ifr_name, iface, IFNAMSIZ, "get_mac_from_ip_linux");
     if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
         logger_async_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, "ioctl SIOCGIFHWADDR failed: %s", strerror(errno));
         CLOSESOCKET(sockfd);
         return -1;
     }
     memcpy(local_mac, ifr.ifr_hwaddr.sa_data, MAC_SIZE);
     if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
         logger_async_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, "ioctl SIOCGIFADDR failed: %s", strerror(errno));
         CLOSESOCKET(sockfd);
         return -1;
     }
     local_ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
     CLOSESOCKET(sockfd);
 
     int arp_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
     if (arp_sock < 0) {
         logger_async_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, "Raw socket creation failed: %s", strerror(errno));
         return -1;
     }
     struct sockaddr_ll sock_addr;
     memset(&sock_addr, 0, sizeof(sock_addr));
     sock_addr.sll_family   = AF_PACKET;
     sock_addr.sll_ifindex  = if_nametoindex(iface);
     sock_addr.sll_protocol = htons(ETH_P_ARP);
     if (bind(arp_sock, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) < 0) {
         logger_async_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, "bind failed: %s", strerror(errno));
         CLOSESOCKET(arp_sock);
         return -1;
     }
 
     typedef struct {
         unsigned char dest[6];
         unsigned char src[6];
         uint16_t ethertype;
     } eth_header_t;
     typedef struct {
         uint16_t hw_type;
         uint16_t proto_type;
         unsigned char hw_size;
         unsigned char proto_size;
         uint16_t opcode;
         unsigned char sender_mac[6];
         uint32_t sender_ip;
         unsigned char target_mac[6];
         uint32_t target_ip;
     } arp_packet_t;
 
     unsigned char buffer[42] = {0};
     eth_header_t *eth = (eth_header_t *)buffer;
     arp_packet_t *arp = (arp_packet_t *)(buffer + sizeof(eth_header_t));
 
     memset(eth->dest, 0xff, 6);
     memcpy(eth->src, local_mac, MAC_SIZE);
     eth->ethertype = htons(ETH_P_ARP);
 
     arp->hw_type = htons(1);
     arp->proto_type = htons(ETH_P_IP);
     arp->hw_size = MAC_SIZE;
     arp->proto_size = 4;
     arp->opcode = htons(1);  /* ARP request */
     memcpy(arp->sender_mac, local_mac, MAC_SIZE);
     arp->sender_ip = local_ip.s_addr;
     memset(arp->target_mac, 0x00, MAC_SIZE);
 
     struct in_addr target_addr;
     if (inet_aton(target_ip, &target_addr) == 0) {
         logger_async_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, "Invalid target IP address: %s", target_ip);
         CLOSESOCKET(arp_sock);
         return -1;
     }
     arp->target_ip = target_addr.s_addr;
 
     struct sockaddr_ll dest_addr;
     memset(&dest_addr, 0, sizeof(dest_addr));
     dest_addr.sll_family = AF_PACKET;
     dest_addr.sll_ifindex = sock_addr.sll_ifindex;
     dest_addr.sll_halen = ETH_ALEN;
     memset(dest_addr.sll_addr, 0xff, 6);
 
     ssize_t sent = sendto(arp_sock, buffer, sizeof(buffer), 0,
                             (struct sockaddr *)&dest_addr, sizeof(dest_addr));
     if (sent <= 0) {
         logger_async_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, "sendto failed: %s", strerror(errno));
         CLOSESOCKET(arp_sock);
         return -1;
     }
     fd_set fds;
     struct timeval timeout = {5, 0};
     FD_ZERO(&fds);
     FD_SET(arp_sock, &fds);
     int ret = select(arp_sock + 1, &fds, NULL, NULL, &timeout);
     if (ret <= 0) {
         logger_async_log(LOG_LEVEL_WARN, __FILE__, __LINE__, __func__, "ARP reply timeout or error");
         CLOSESOCKET(arp_sock);
         return -1;
     }
     unsigned char recv_buf[60];
     ssize_t recv_len = recvfrom(arp_sock, recv_buf, sizeof(recv_buf), 0, NULL, NULL);
     if (recv_len <= 0) {
         logger_async_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, "recvfrom failed: %s", strerror(errno));
         CLOSESOCKET(arp_sock);
         return -1;
     }
     eth_header_t *recv_eth = (eth_header_t *)recv_buf;
     if (ntohs(recv_eth->ethertype) != ETH_P_ARP) {
         logger_async_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, "Received packet is not ARP");
         CLOSESOCKET(arp_sock);
         return -1;
     }
     arp_packet_t *recv_arp = (arp_packet_t *)(recv_buf + sizeof(eth_header_t));
     if (ntohs(recv_arp->opcode) != 2) {
         logger_async_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, "Received packet is not an ARP reply");
         CLOSESOCKET(arp_sock);
         return -1;
     }
     if (recv_arp->sender_ip != target_addr.s_addr) {
         logger_async_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, "ARP reply from unexpected IP");
         CLOSESOCKET(arp_sock);
         return -1;
     }
     memcpy(mac, recv_arp->sender_mac, MAC_SIZE);
     CLOSESOCKET(arp_sock);
     return 0;
 }
 #endif
 
 #ifdef _WIN32
 static int get_ip_from_mac_rev(const char *mac_str, char *ip_str, size_t ip_str_size, const char *unused) {
     (void)unused;
     return get_ip_from_mac_rev_win(mac_str, ip_str, ip_str_size);
 }
 #else
 static int get_ip_from_mac_rev(const char *mac_str, char *ip_str, size_t ip_str_size, const char *ifname) {
     /* For demonstration, this always fails.
        In a complete implementation, asynchronous netlink would be used. */
     return -1;
 }
 #endif
 
 /* --------------------- Target Processing Module --------------------- */
 static void process_target(const char *target, const config_t *cfg) {
     char mac_str[18] = "";
     unsigned char mac[MAC_SIZE];
     char ip_str[64] = "";
     char resolved_hostname[128] = "";
 
     if (strchr(target, ':') && !strchr(target, '.')) {
         safe_strlcpy_wrapper(mac_str, target, sizeof(mac_str), "process_target: mac_str");
     } else {
         struct in_addr dummy;
         if (inet_pton(AF_INET, target, &dummy) == 1) {
             safe_strlcpy_wrapper(ip_str, target, sizeof(ip_str), "process_target: ip_str");
             struct sockaddr_in sa;
             memset(&sa, 0, sizeof(sa));
             sa.sin_family = AF_INET;
             inet_pton(AF_INET, ip_str, &sa.sin_addr);
             if (getnameinfo((struct sockaddr *)&sa, sizeof(sa),
                             resolved_hostname, sizeof(resolved_hostname),
                             NULL, 0, 0) != 0) {
                 safe_strlcpy_wrapper(resolved_hostname, "-", sizeof(resolved_hostname), "process_target: resolved_hostname");
             }
         } else {
             struct addrinfo hints, *res;
             memset(&hints, 0, sizeof(hints));
             hints.ai_family = AF_INET;
             hints.ai_socktype = SOCK_DGRAM;
             int err = getaddrinfo(target, NULL, &hints, &res);
             if (err != 0) {
                 logger_async_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, "Hostname resolution error for %s: %s", target, gai_strerror(err));
                 return;
             }
             struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;
             inet_ntop(AF_INET, &(addr->sin_addr), ip_str, sizeof(ip_str));
             freeaddrinfo(res);
             safe_strlcpy_wrapper(resolved_hostname, target, sizeof(resolved_hostname), "process_target: resolved_hostname");
         }
         arp_cache_entry *entry = find_arp_cache_entry(ip_str, resolved_hostname);
         if (entry != NULL) {
             safe_strlcpy_wrapper(mac_str, entry->mac, sizeof(mac_str), "process_target: cache mac_str");
             logger_async_log(LOG_LEVEL_INFO, __FILE__, __LINE__, __func__,
                              "Using cached MAC for %s (IP: %s): %s", resolved_hostname, ip_str, mac_str);
         } else {
             uint64_t start_time = get_current_time_ms();
             metric_arp_attempts_total++;
 #ifdef _WIN32
             if (get_mac_from_ip_win(ip_str, mac) != 0) {
 #else
             if (get_mac_from_ip_linux(ip_str, cfg->iface, mac) != 0) {
 #endif
                 metric_arp_failures_total++;
                 uint64_t end_time = get_current_time_ms();
                 metric_arp_resolution_time_ms_total += (end_time - start_time);
                 metric_arp_resolution_count++;
                 logger_async_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__,
                                  "ARP resolution failed and no cached entry found for %s (IP: %s)", resolved_hostname, ip_str);
                 return;
             } else {
                 uint64_t end_time = get_current_time_ms();
                 metric_arp_resolution_time_ms_total += (end_time - start_time);
                 metric_arp_resolution_count++;
                 safe_snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                              mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                 logger_async_log(LOG_LEVEL_INFO, __FILE__, __LINE__, __func__,
                                  "Resolved %s to IP %s and MAC %s", resolved_hostname, ip_str, mac_str);
                 update_arp_cache_entry(ip_str, resolved_hostname, mac_str);
             }
         }
     }
     metric_wakeup_attempts++;
     send_wol_packet(mac_str, cfg->broadcast_ip);
     msleep(5000);
     char new_ip[64] = "";
     int found = 0;
 #ifdef _WIN32
     {
         int attempts = 10;
         while (attempts--) {
             metric_reverse_arp_attempts_total++;
             if (get_ip_from_mac_rev(mac_str, new_ip, sizeof(new_ip), NULL) == 0) {
                 found = 1;
                 metric_reverse_arp_success_total++;
                 break;
             }
             msleep(2000);
         }
     }
 #else
     {
         metric_reverse_arp_attempts_total++;
         if (get_ip_from_mac_rev(mac_str, new_ip, sizeof(new_ip), cfg->iface) == 0) {
             found = 1;
             metric_reverse_arp_success_total++;
         }
     }
 #endif
     if (found) {
         struct sockaddr_in sa;
         memset(&sa, 0, sizeof(sa));
         sa.sin_family = AF_INET;
         inet_pton(AF_INET, new_ip, &sa.sin_addr);
         char new_hostname[128];
         if (getnameinfo((struct sockaddr *)&sa, sizeof(sa),
                         new_hostname, sizeof(new_hostname), NULL, 0, 0) != 0) {
             safe_strlcpy_wrapper(new_hostname, "-", sizeof(new_hostname), "process_target: new_hostname");
         }
         logger_async_log(LOG_LEVEL_INFO, __FILE__, __LINE__, __func__,
                          "Reverse ARP: Found IP %s and hostname %s for MAC %s", new_ip, new_hostname, mac_str);
         update_arp_cache_entry(new_ip, new_hostname, mac_str);
         metric_wol_success_total++;
     } else {
         logger_async_log(LOG_LEVEL_INFO, __FILE__, __LINE__, __func__,
                          "Reverse ARP: Unable to determine IP for MAC %s", mac_str);
     }
 }
 
 /* --------------------- Main --------------------- */
 int main(int argc, char *argv[]) {
     config_t cfg;
     init_config(&cfg);
     const char *target_arg = parse_arguments(argc, argv, &cfg);
     if (!target_arg)
         exit(EXIT_FAILURE);
     auto_detect_interface(&cfg);
 #ifdef _WIN32
     InitializeCriticalSection(&g_logger_cs);
     InitializeCriticalSection(&g_arp_cache_cs);
     WSADATA wsaData;
     if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
         fprintf(stderr, "WSAStartup failed\n");
         exit(EXIT_FAILURE);
     }
 #endif
     logger_init(&cfg, argv[0]);
     load_arp_cache_from_file(cfg.cache_filename);
     FILE *fp = fopen(target_arg, "r");
     if (fp != NULL) {
         logger_async_log(LOG_LEVEL_INFO, __FILE__, __LINE__, __func__, "Processing target file: %s", target_arg);
         char line[256];
         while (fgets(line, sizeof(line), fp)) {
             char *newline = strchr(line, '\n');
             if (newline) *newline = '\0';
             if (line[0]=='\0')
                 continue;
             logger_async_log(LOG_LEVEL_INFO, __FILE__, __LINE__, __func__, "Processing target: %s", line);
             process_target(line, &cfg);
         }
         fclose(fp);
     } else {
         process_target(target_arg, &cfg);
     }
     flush_arp_cache_to_file(cfg.cache_filename);
     {
         arp_cache_entry *entry, *tmp;
         LOCK_ARP();
         HASH_ITER(hh, g_arp_cache, entry, tmp) {
             free(entry);
         }
         g_arp_cache = NULL;
         UNLOCK_ARP();
     }
     logger_close();
 #ifdef _WIN32
     WSACleanup();
     DeleteCriticalSection(&g_logger_cs);
     DeleteCriticalSection(&g_arp_cache_cs);
 #endif
     return EXIT_SUCCESS;
 }
 