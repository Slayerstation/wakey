#include "logger.h"
#include "utils.h" // For safe_snprintf

/* Global logger state */
#ifdef _WIN32
static HANDLE g_hEventLog = NULL;
#else
// For POSIX when not using file logging
#endif
static FILE *g_log_fp = NULL;
static char g_log_filename[256] = "";
static int g_log_max_size = DEFAULT_LOG_MAX_SIZE;
static int g_log_rotation_interval = DEFAULT_LOG_ROTATION_INTERVAL;
static time_t g_last_rotation_time = 0;

static int g_enable_remote_logging = 0;
static int g_remote_log_socket = -1;
static struct sockaddr_in g_remote_log_addr;
static int g_use_file_logging = 0;

/* Asynchronous Logging Queue */
static LOCK_T log_queue_mutex;
static COND_T log_queue_cond;
static THREAD_T log_thread_handle;

typedef struct log_msg {
    LogLevel level;
    char *msg;
    struct log_msg *next;
} log_msg_t;

static log_msg_t *log_queue_head = NULL;
static log_msg_t *log_queue_tail = NULL;
static volatile int log_thread_running = 1;

/* Forward declaration */
static void check_log_rotation(void);
static THREAD_RET_T logger_thread_func(void *arg);

/* Remote logging helper */
static void logger_remote_send(const char *msg) {
    if (g_remote_log_socket == -1) return;
    sendto(g_remote_log_socket, msg, (int)strlen(msg), 0,
           (struct sockaddr*)&g_remote_log_addr, sizeof(g_remote_log_addr));
}

/* Queue the log message */
void logger_queue_log(LogLevel level, const char *file, int line, const char *func, const char *format, ...) {
    char buf[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args); // Use standard vsnprintf here, full message built later
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
    int base_len = safe_snprintf(fullmsg, sizeof(fullmsg), "logger_queue_log", "[%s] %s: %s",
             timestr,
             (level == LOG_LEVEL_DEBUG ? "DEBUG" :
              level == LOG_LEVEL_INFO  ? "INFO"  :
              level == LOG_LEVEL_WARN  ? "WARN"  : "ERROR"),
             buf);

    int add_context = (level == LOG_LEVEL_ERROR);
#ifdef DEBUG
    if (level == LOG_LEVEL_DEBUG || level == LOG_LEVEL_WARN) add_context = 1;
#endif
    if (add_context && base_len > 0 && (size_t)base_len < sizeof(fullmsg) - 1) {
        safe_snprintf(fullmsg + base_len, sizeof(fullmsg) - base_len, "logger_queue_log context", " (at %s:%d in %s)", file, line, func);
    }

#ifdef ENABLE_STACKTRACE
    if (level == LOG_LEVEL_ERROR && strlen(fullmsg) < sizeof(fullmsg) - 100) { // Check space
#if !defined(_WIN32)
        void *bt_buffer[10];
        int nptrs = backtrace(bt_buffer, 10);
        char **strings = backtrace_symbols(bt_buffer, nptrs);
        if (strings != NULL) {
            strncat(fullmsg, "\nStack trace:\n", sizeof(fullmsg)-strlen(fullmsg)-1);
            for (int i = 0; i < nptrs && strlen(fullmsg) < sizeof(fullmsg) - 100; i++) {
                strncat(fullmsg, strings[i], sizeof(fullmsg)-strlen(fullmsg)-1);
                strncat(fullmsg, "\n", sizeof(fullmsg)-strlen(fullmsg)-1);
            }
            free(strings);
        }
#else
        strncat(fullmsg, "\nStack trace not available on Windows build.", sizeof(fullmsg)-strlen(fullmsg)-1);
#endif
    }
#endif // ENABLE_STACKTRACE

    log_msg_t *node = malloc(sizeof(log_msg_t));
    if (!node) { fprintf(stderr, "Out of memory in logger_queue_log\n"); return; }
    node->msg = strdup(fullmsg);
    if (!node->msg) { free(node); fprintf(stderr, "Out of memory duplicating log message\n"); return; }
    node->level = level;
    node->next = NULL;

    LOCK(&log_queue_mutex);
    if (log_queue_tail) {
        log_queue_tail->next = node;
        log_queue_tail = node;
    } else {
        log_queue_head = log_queue_tail = node;
    }
    COND_SIGNAL(&log_queue_cond);
    UNLOCK(&log_queue_mutex);
}


static void check_log_rotation(void) {
    if (!g_use_file_logging || !g_log_fp) return;

    long current_size = -1;
    fflush(g_log_fp); // Ensure data is written before checking size
#ifdef _WIN32
    int fd = _fileno(g_log_fp);
    if (fd != -1) current_size = _filelength(fd);
#else
    int fd = fileno(g_log_fp);
    if (fd != -1) {
        struct stat st;
        if (fstat(fd, &st) == 0) current_size = st.st_size;
    }
#endif

    time_t now = time(NULL);
    if (current_size < 0) { // Error getting size
        fprintf(stderr, "Could not get log file size.\n");
        return; // Avoid rotating on error
    }

    if (current_size >= g_log_max_size || (now - g_last_rotation_time >= g_log_rotation_interval)) {
        fclose(g_log_fp);
        g_log_fp = NULL;

        char backup_filename[300];
        safe_snprintf(backup_filename, sizeof(backup_filename), "check_log_rotation backup name", "%s.%ld", g_log_filename, (long)now);

        if (rename(g_log_filename, backup_filename) != 0) {
            fprintf(stderr, "Log rotation: rename failed: %s\n", strerror(errno));
            // Try to reopen original file anyway
        } else {
            // Compress the backup file in the background (simple system call)
            char command[512];
            safe_snprintf(command, sizeof(command), "check_log_rotation gzip", "gzip -f \"%s\" &", backup_filename); // Added quotes and background
            system(command);
        }

        g_log_fp = fopen(g_log_filename, "a");
        if (!g_log_fp) {
            fprintf(stderr, "Unable to reopen log file %s after rotation: %s\n", g_log_filename, strerror(errno));
            // Logging is effectively stopped here until resolved externally
        } else {
            g_last_rotation_time = now;
            fprintf(g_log_fp, "[%ld] Log rotated.\n", (long)now); // Log rotation event
            fflush(g_log_fp);
        }
    }
}


static THREAD_RET_T logger_thread_func(void *arg) {
    (void)arg;
    while (log_thread_running || log_queue_head != NULL) {
        log_msg_t *node = NULL;

        LOCK(&log_queue_mutex);
        while (log_queue_head == NULL && log_thread_running) {
            COND_WAIT(&log_queue_cond, &log_queue_mutex);
        }
        if (log_queue_head) {
            node = log_queue_head;
            log_queue_head = node->next;
            if (log_queue_head == NULL) log_queue_tail = NULL;
        }
        UNLOCK(&log_queue_mutex);

        if (node) {
            // Actual logging happens here
            if (g_use_file_logging) {
                if (g_log_fp) {
                    check_log_rotation(); // Check before writing
                    if (g_log_fp) { // Re-check if rotation closed it
                       fprintf(g_log_fp, "%s\n", node->msg);
                       fflush(g_log_fp); // Flush after each message
                    }
                } else {
                    // Log file isn't open (rotation failed?), maybe log to stderr?
                    fprintf(stderr, "Log file not available: %s\n", node->msg);
                }
            }
#ifdef _WIN32
            else if (g_hEventLog) {
                WORD type;
                switch(node->level) {
                    case LOG_LEVEL_DEBUG: case LOG_LEVEL_INFO:  type = EVENTLOG_INFORMATION_TYPE; break;
                    case LOG_LEVEL_WARN:  type = EVENTLOG_WARNING_TYPE; break;
                    case LOG_LEVEL_ERROR: type = EVENTLOG_ERROR_TYPE; break;
                    default: type = EVENTLOG_INFORMATION_TYPE;
                }
                LPCSTR strings[1] = { node->msg };
                ReportEvent(g_hEventLog, type, 0, 0, NULL, 1, 0, strings, NULL);
            }
#else // POSIX Syslog
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
            // Remote logging
            if (g_enable_remote_logging) {
                logger_remote_send(node->msg);
            }

            // Clean up message
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


void logger_init(const config_t *cfg, const char *progname) {
    g_log_max_size = cfg->log_max_size > 0 ? cfg->log_max_size : DEFAULT_LOG_MAX_SIZE;
    g_log_rotation_interval = cfg->log_rotation_interval > 0 ? cfg->log_rotation_interval : DEFAULT_LOG_ROTATION_INTERVAL;

    if (cfg->log_file[0] != '\0') {
        safe_strlcpy(g_log_filename, cfg->log_file, sizeof(g_log_filename), "logger_init: g_log_filename");
        g_log_fp = fopen(g_log_filename, "a");
        if (!g_log_fp) {
            fprintf(stderr, "Unable to open log file %s: %s. Exiting.\n", g_log_filename, strerror(errno));
            exit(EXIT_FAILURE);
        }
        g_use_file_logging = 1;
        g_last_rotation_time = time(NULL);
    } else {
        g_use_file_logging = 0;
#ifdef _WIN32
        g_hEventLog = RegisterEventSource(NULL, progname);
        if (!g_hEventLog) {
            fprintf(stderr, "RegisterEventSource failed: %lu\n", GetLastError());
            // Non-fatal, will just not log to Event Log
        }
#else // POSIX Syslog
        openlog(progname, LOG_PID | LOG_CONS, LOG_USER);
#endif
    }

    // Remote Logging Setup
    if (cfg->enable_remote_logging && cfg->remote_log_server[0] != '\0') {
        g_enable_remote_logging = 1;
#ifdef _WIN32 // WSAStartup should ideally be called once in main
        // WSADATA wsaData;
        // if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        //     fprintf(stderr, "WSAStartup failed for remote logging.\n");
        //     g_enable_remote_logging = 0; // Disable if startup fails
        // }
#endif
        if (g_enable_remote_logging) {
            g_remote_log_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (g_remote_log_socket < 0) {
                fprintf(stderr, "Failed to create remote log socket: %s\n", strerror(errno));
                g_enable_remote_logging = 0;
            } else {
                memset(&g_remote_log_addr, 0, sizeof(g_remote_log_addr));
                g_remote_log_addr.sin_family = AF_INET;
                g_remote_log_addr.sin_port = htons(cfg->remote_log_port);
                // Use inet_pton for better IP validation
                if (inet_pton(AF_INET, cfg->remote_log_server, &g_remote_log_addr.sin_addr) <= 0) {
                    fprintf(stderr, "Invalid remote log server IP: %s. Disabling remote logging.\n", cfg->remote_log_server);
                    CLOSESOCKET(g_remote_log_socket);
                    g_remote_log_socket = -1;
                    g_enable_remote_logging = 0;
                }
            }
        }
    }

    // Initialize sync primitives and start thread
    LOCK_INIT(&log_queue_mutex);
    COND_INIT(&log_queue_cond);
    if (THREAD_CREATE(&log_thread_handle, logger_thread_func, NULL) != 0) {
        fprintf(stderr, "Failed to create logging thread. Exiting.\n");
        // Cleanup already opened resources
        if (g_log_fp) fclose(g_log_fp);
#ifdef _WIN32
        if (g_hEventLog) DeregisterEventSource(g_hEventLog);
#else
        if (!g_use_file_logging) closelog();
#endif
        exit(EXIT_FAILURE);
    }

    LOG(LOG_LEVEL_INFO, "Logger initialized.");
}

void logger_close(void) {
    LOG(LOG_LEVEL_INFO, "Shutting down logger.");

    // Signal thread to exit and wait for it
    log_thread_running = 0;
    LOCK(&log_queue_mutex);
    COND_SIGNAL(&log_queue_cond);
    UNLOCK(&log_queue_mutex);

    THREAD_JOIN(log_thread_handle);

    // Clean up resources
    LOCK_DESTROY(&log_queue_mutex);
    // COND_DESTROY(&log_queue_cond); // Not needed on Windows, safe on POSIX

    if (g_log_fp) fclose(g_log_fp);
    g_log_fp = NULL;

#ifdef _WIN32
    if (g_hEventLog) DeregisterEventSource(g_hEventLog);
    // WSACleanup should happen once in main
#else // POSIX Syslog
    if (!g_use_file_logging) closelog();
#endif
    if (g_remote_log_socket != -1) {
        CLOSESOCKET(g_remote_log_socket);
        g_remote_log_socket = -1;
    }

    // Free any remaining messages in the queue (should be empty ideally)
    log_msg_t *node = log_queue_head;
    while(node) {
        log_msg_t *next = node->next;
        free(node->msg);
        free(node);
        node = next;
    }
    log_queue_head = log_queue_tail = NULL;
}