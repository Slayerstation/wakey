#include "metrics.h"
#include "utils.h"   // For safe_snprintf
#include "config.h"  // For METRICS_PORT

/* Global instrumentation counters definition */
volatile uint64_t metric_wakeup_attempts = 0;
volatile uint64_t metric_wol_success_total = 0;
volatile uint64_t metric_arp_attempts_total = 0;
volatile uint64_t metric_arp_failures_total = 0;
volatile uint64_t metric_arp_resolution_time_ms_total = 0;
volatile uint64_t metric_arp_resolution_count = 0;
volatile uint64_t metric_reverse_arp_attempts_total = 0;
volatile uint64_t metric_reverse_arp_success_total = 0;

static THREAD_T metrics_thread_handle;
static volatile int metrics_thread_running = 0;
static int metrics_server_fd = -1;

static THREAD_RET_T metrics_thread_func(void *arg) {
    (void)arg;
    struct sockaddr_in serv_addr;

    metrics_server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (metrics_server_fd < 0) {
        LOG(LOG_LEVEL_ERROR, "Metrics: Failed to create socket: %s", strerror(errno));
        return (THREAD_RET_T)1;
    }

    int opt = 1;
#ifdef _WIN32
    if (setsockopt(metrics_server_fd, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt)) < 0) {
        LOG(LOG_LEVEL_ERROR, "Metrics: Failed to set SO_REUSEADDR: %s", strerror(errno));
        CLOSESOCKET(metrics_server_fd); metrics_server_fd = -1; return (THREAD_RET_T)1;
    }
#else
    if (setsockopt(metrics_server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        LOG(LOG_LEVEL_ERROR, "Metrics: Failed to set SO_REUSEADDR: %s", strerror(errno));
        CLOSESOCKET(metrics_server_fd); metrics_server_fd = -1; return (THREAD_RET_T)1;
    }
#endif

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(METRICS_PORT);

    if (bind(metrics_server_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        LOG(LOG_LEVEL_ERROR, "Metrics: Failed to bind to port %d: %s", METRICS_PORT, strerror(errno));
        CLOSESOCKET(metrics_server_fd); metrics_server_fd = -1; return (THREAD_RET_T)1;
    }

    if (listen(metrics_server_fd, 5) < 0) {
        LOG(LOG_LEVEL_ERROR, "Metrics: Failed to listen: %s", strerror(errno));
        CLOSESOCKET(metrics_server_fd); metrics_server_fd = -1; return (THREAD_RET_T)1;
    }

    LOG(LOG_LEVEL_INFO, "Metrics server listening on port %d", METRICS_PORT);
    metrics_thread_running = 1;

    while (metrics_thread_running) {
        struct sockaddr_in client_addr;
        #ifdef _WIN32
            int addrlen = sizeof(client_addr);
        #else
            socklen_t addrlen = sizeof(client_addr);
        #endif
        int client_fd = accept(metrics_server_fd, (struct sockaddr *)&client_addr, &addrlen);

        if (!metrics_thread_running) break; // Check after potentially blocking accept

        if (client_fd < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) { // Ignore non-blocking errors if applicable
                 LOG(LOG_LEVEL_WARN, "Metrics: accept() failed: %s", strerror(errno));
            }
            msleep(100); // Avoid busy-looping on errors
            continue;
        }

        char metrics_buffer[2048]; // Increased buffer size
        char temp_buffer[512]; // Buffer for individual metric lines

        // Clear buffer
        metrics_buffer[0] = '\0';

        // Helper macro for appending metrics
        #define APPEND_METRIC(name, help, type, value_fmt, value) \
            safe_snprintf(temp_buffer, sizeof(temp_buffer), "metrics_thread_func", \
                "# HELP " name " " help "\n# TYPE " name " " type "\n" name " " value_fmt "\n", value); \
            strncat(metrics_buffer, temp_buffer, sizeof(metrics_buffer) - strlen(metrics_buffer) - 1)

        APPEND_METRIC("enterprise_wol_wake_attempts_total", "Total wake-up attempts", "counter", "%llu", metric_wakeup_attempts);
        APPEND_METRIC("enterprise_wol_wake_success_total", "Total successful wake-ups", "counter", "%llu", metric_wol_success_total);
        APPEND_METRIC("enterprise_wol_arp_attempts_total", "Total ARP resolution attempts", "counter", "%llu", metric_arp_attempts_total);
        APPEND_METRIC("enterprise_wol_arp_failures_total", "Total ARP resolution failures", "counter", "%llu", metric_arp_failures_total);

        double avg_arp_time_sec = 0.0;
        if (metric_arp_resolution_count > 0) {
            avg_arp_time_sec = ((double)metric_arp_resolution_time_ms_total / metric_arp_resolution_count) / 1000.0;
        }
        APPEND_METRIC("enterprise_wol_arp_resolution_time_seconds", "Average ARP resolution time", "gauge", "%f", avg_arp_time_sec);
        APPEND_METRIC("enterprise_wol_reverse_arp_attempts_total", "Total reverse ARP attempts", "counter", "%llu", metric_reverse_arp_attempts_total);
        APPEND_METRIC("enterprise_wol_reverse_arp_success_total", "Total successful reverse ARP resolutions", "counter", "%llu", metric_reverse_arp_success_total);

        #undef APPEND_METRIC

        char response_header[256];
        size_t metrics_len = strlen(metrics_buffer);
        int header_len = safe_snprintf(response_header, sizeof(response_header), "metrics_thread_func header",
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n", metrics_len);

        // Send header and body
        send(client_fd, response_header, header_len, 0);
        send(client_fd, metrics_buffer, metrics_len, 0);

        CLOSESOCKET(client_fd);
    }

    LOG(LOG_LEVEL_INFO, "Metrics server shutting down.");
    CLOSESOCKET(metrics_server_fd);
    metrics_server_fd = -1;
    metrics_thread_running = 0;
    return (THREAD_RET_T)0;
}

void metrics_init(void) {
    if (metrics_thread_running) {
        LOG(LOG_LEVEL_WARN, "Metrics server already initialized.");
        return;
    }
    if (THREAD_CREATE(&metrics_thread_handle, metrics_thread_func, NULL) != 0) {
        LOG(LOG_LEVEL_ERROR, "Failed to create metrics thread.");
    } else {
        // Detach the thread - let it run independently
        #ifndef _WIN32
            THREAD_DETACH(metrics_thread_handle);
        #endif
        // On Windows, CreateThread starts it; CloseHandle detaches if needed, but we might want to join on shutdown
    }
}

// Optional shutdown function
void metrics_shutdown(void) {
    if (!metrics_thread_running) return;

    LOG(LOG_LEVEL_INFO, "Attempting to shut down metrics server thread.");
    metrics_thread_running = 0;

    // To interrupt accept(), we can close the listening socket from this thread
    if (metrics_server_fd >= 0) {
        CLOSESOCKET(metrics_server_fd);
        metrics_server_fd = -1; // Mark as closed
    }

    // Optionally join the thread if required (might block)
    #ifdef _WIN32
       // WaitForSingleObject(metrics_thread_handle, 2000); // Wait briefly
       CloseHandle(metrics_thread_handle); // Close handle
    #else
       // pthread_cancel(metrics_thread_handle); // Force cancel if needed
       // THREAD_JOIN(metrics_thread_handle); // Join if needed
    #endif
    metrics_thread_handle = (THREAD_T)0; // Reset handle
}