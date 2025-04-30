#ifndef CONFIG_H
#define CONFIG_H

#include "platform.h"

#define DEFAULT_BROADCAST_IP "255.255.255.255"
#define DEFAULT_INTERFACE    "auto"
#define DEFAULT_CACHE_FILE   "arp_cache.txt"
#define DEFAULT_LOG_MAX_SIZE 1048576  /* 1MB */
#define DEFAULT_LOG_ROTATION_INTERVAL 86400  /* Rotate daily (seconds) */
#define METRICS_PORT         9100

typedef struct config_t {
    char broadcast_ip[64];
    char iface[32];
    char cache_filename[128];
    char log_file[256];
    int  log_max_size;
    int  enable_remote_logging;
    char remote_log_server[128];
    int  remote_log_port;
    int  log_rotation_interval;
} config_t;

void init_config(config_t *cfg);
void print_usage(const char *progname);
const char *parse_arguments(int argc, char **argv, config_t *cfg);

#endif // CONFIG_H