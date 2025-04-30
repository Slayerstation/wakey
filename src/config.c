#include "config.h"
#include "utils.h" // For safe_strlcpy

void init_config(config_t *cfg) {
    safe_strlcpy(cfg->broadcast_ip, DEFAULT_BROADCAST_IP, sizeof(cfg->broadcast_ip), "init_config: broadcast_ip");
    safe_strlcpy(cfg->iface, DEFAULT_INTERFACE, sizeof(cfg->iface), "init_config: iface");
    safe_strlcpy(cfg->cache_filename, DEFAULT_CACHE_FILE, sizeof(cfg->cache_filename), "init_config: cache_filename");
    cfg->log_file[0] = '\0';
    cfg->log_max_size = DEFAULT_LOG_MAX_SIZE;
    cfg->enable_remote_logging = 0;
    cfg->remote_log_server[0] = '\0';
    cfg->remote_log_port = 514; // Default syslog port
    cfg->log_rotation_interval = DEFAULT_LOG_ROTATION_INTERVAL;
}

void print_usage(const char *progname) {
    fprintf(stderr,
        "Usage: %s [options] <target>\n"
        "Options:\n"
        "  -b, --broadcast <ip>      Set broadcast IP (default: %s)\n"
        "  -i, --interface <iface>   Set network interface (default: %s)\n"
        "  -c, --cachefile <file>    Set ARP cache file (default: %s)\n"
        "  -l, --logfile <file>      Set log file (if omitted, syslog/Event Log is used)\n"
        "  -r, --remote <srv:port>   Enable remote logging (e.g. 192.168.1.100:514)\n"
        "  -h, --help                Display this help message\n",
        progname, DEFAULT_BROADCAST_IP, DEFAULT_INTERFACE, DEFAULT_CACHE_FILE);
}

const char *parse_arguments(int argc, char **argv, config_t *cfg) {
    const char *progname = argv[0];
    const char *target = NULL;
    for (int i = 1; i < argc; i++) {
        char *arg = argv[i];
        if (arg[0] == '-') {
            // Handle long options
            if (arg[1] == '-') {
                if (strcmp(arg, "--help") == 0) {
                    print_usage(progname);
                    exit(EXIT_SUCCESS);
                } else if (strncmp(arg, "--broadcast=", 12) == 0) {
                    safe_strlcpy(cfg->broadcast_ip, arg + 12, sizeof(cfg->broadcast_ip), "parse_arguments: broadcast_ip");
                } else if (strncmp(arg, "--interface=", 12) == 0) {
                    safe_strlcpy(cfg->iface, arg + 12, sizeof(cfg->iface), "parse_arguments: iface");
                } else if (strncmp(arg, "--cachefile=", 12) == 0) {
                    safe_strlcpy(cfg->cache_filename, arg + 12, sizeof(cfg->cache_filename), "parse_arguments: cache_filename");
                } else if (strncmp(arg, "--logfile=", 10) == 0) {
                    safe_strlcpy(cfg->log_file, arg + 10, sizeof(cfg->log_file), "parse_arguments: log_file");
                } else if (strncmp(arg, "--remote=", 9) == 0) {
                    const char *value = arg + 9;
                    char *colon = strchr(value, ':');
                    if (!colon) {
                        fprintf(stderr, "Remote logging option requires format server:port\n");
                        print_usage(progname); exit(EXIT_FAILURE);
                    }
                    size_t len = colon - value;
                    if (len >= sizeof(cfg->remote_log_server)) {
                        fprintf(stderr, "Remote log server name too long.\n");
                        print_usage(progname); exit(EXIT_FAILURE);
                    }
                    memcpy(cfg->remote_log_server, value, len);
                    cfg->remote_log_server[len] = '\0';
                    cfg->remote_log_port = atoi(colon + 1);
                    cfg->enable_remote_logging = 1;
                } else {
                    fprintf(stderr, "Unknown option '%s'\n", arg);
                    print_usage(progname); return NULL;
                }
            } else { // Handle short options
                size_t len = strlen(arg);
                for (size_t j = 1; j < len; j++) {
                    char opt = arg[j];
                    const char *value = NULL;
                    // Check if the value is attached or in the next argument
                    if (strchr("biclr", opt)) { // Options requiring arguments
                        if (j + 1 < len) {
                            value = &arg[j + 1]; j = len; // Value attached
                        } else if (i + 1 < argc) {
                            value = argv[++i]; // Value is next arg
                        } else {
                            fprintf(stderr, "Option -%c requires an argument.\n", opt);
                            print_usage(progname); return NULL;
                        }
                    }
                    switch (opt) {
                        case 'h': print_usage(progname); exit(EXIT_SUCCESS);
                        case 'b': safe_strlcpy(cfg->broadcast_ip, value, sizeof(cfg->broadcast_ip), "parse_arguments: broadcast_ip"); break;
                        case 'i': safe_strlcpy(cfg->iface, value, sizeof(cfg->iface), "parse_arguments: iface"); break;
                        case 'c': safe_strlcpy(cfg->cache_filename, value, sizeof(cfg->cache_filename), "parse_arguments: cache_filename"); break;
                        case 'l': safe_strlcpy(cfg->log_file, value, sizeof(cfg->log_file), "parse_arguments: log_file"); break;
                        case 'r': {
                                char *colon = strchr(value, ':');
                                if (!colon) {
                                    fprintf(stderr, "Option -r requires format server:port.\n");
                                    print_usage(progname); return NULL;
                                }
                                size_t sv_len = colon - value;
                                if (sv_len >= sizeof(cfg->remote_log_server)) {
                                     fprintf(stderr, "Remote log server name too long.\n");
                                     print_usage(progname); return NULL;
                                }
                                memcpy(cfg->remote_log_server, value, sv_len);
                                cfg->remote_log_server[sv_len] = '\0';
                                cfg->remote_log_port = atoi(colon + 1);
                                cfg->enable_remote_logging = 1;
                            } break;
                        default: fprintf(stderr, "Unknown option: -%c\n", opt); print_usage(progname); return NULL;
                    }
                }
            }
        } else { // Positional argument (target)
            if (target == NULL) target = arg;
            else {
                fprintf(stderr, "Multiple target arguments provided.\n");
                print_usage(progname); return NULL;
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