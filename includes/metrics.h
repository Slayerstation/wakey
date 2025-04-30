#ifndef METRICS_H
#define METRICS_H

#include "platform.h"
#include "logger.h" // Include logger for logging within metrics

/* Global instrumentation counters */
extern volatile uint64_t metric_wakeup_attempts;
extern volatile uint64_t metric_wol_success_total;
extern volatile uint64_t metric_arp_attempts_total;
extern volatile uint64_t metric_arp_failures_total;
extern volatile uint64_t metric_arp_resolution_time_ms_total;
extern volatile uint64_t metric_arp_resolution_count;
extern volatile uint64_t metric_reverse_arp_attempts_total;
extern volatile uint64_t metric_reverse_arp_success_total;

/* Start and stop the metrics server */
void metrics_init(void);
void metrics_shutdown(void); // Optional: If graceful shutdown needed

#endif // METRICS_H