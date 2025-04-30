#include "wakey.h" // Includes all other necessary headers via wakey.h

/* --------------------- Target Processing Module --------------------- */
// Processes a single target (IP, hostname, or MAC)
static void process_target(const char *target, const config_t *cfg) {
    LOG(LOG_LEVEL_INFO, "Processing target: %s", target);
    char mac_str[18] = "";
    unsigned char resolved_mac_bytes[MAC_SIZE];
    char ip_str[64] = "";
    char resolved_hostname[128] = "-"; // Default to "-" if resolution fails
    int mac_provided_directly = 0;

    // --- Determine Input Type (MAC, IP, or Hostname) ---
    if (strchr(target, ':') || strchr(target, '-')) { // Likely a MAC address
        if (parse_mac_address(target, resolved_mac_bytes) == 0) {
            safe_snprintf(mac_str, sizeof(mac_str), "process_target mac format", "%02X:%02X:%02X:%02X:%02X:%02X",
                          resolved_mac_bytes[0], resolved_mac_bytes[1], resolved_mac_bytes[2],
                          resolved_mac_bytes[3], resolved_mac_bytes[4], resolved_mac_bytes[5]);
             LOG(LOG_LEVEL_DEBUG, "Target identified as MAC: %s", mac_str);
             mac_provided_directly = 1;
             // Try to find IP/hostname from cache for this MAC (less common lookup)
             // This requires iterating the cache, maybe add a find_by_mac function?
             // For now, skip reverse lookup if MAC is given directly unless needed later.
        } else {
            LOG(LOG_LEVEL_WARN, "Target '%s' looks like MAC but failed to parse.", target);
             // Treat as potential hostname below
        }
    }

    if (!mac_provided_directly) {
        // --- Input is IP or Hostname ---
        struct in_addr dummy_ip;
        if (inet_pton(AF_INET, target, &dummy_ip) == 1) { // Target is an IP address
            safe_strlcpy(ip_str, target, sizeof(ip_str), "process_target: target_is_ip");
            LOG(LOG_LEVEL_DEBUG, "Target identified as IP: %s", ip_str);
            // Try reverse DNS lookup
            struct sockaddr_in sa;
            memset(&sa, 0, sizeof(sa));
            sa.sin_family = AF_INET;
            inet_pton(AF_INET, ip_str, &sa.sin_addr);
            if (getnameinfo((struct sockaddr *)&sa, sizeof(sa), resolved_hostname, sizeof(resolved_hostname), NULL, 0, NI_NAMEREQD) != 0) {
                 // Failed or no hostname, keep default "-"
                 LOG(LOG_LEVEL_DEBUG, "Reverse DNS lookup failed for IP %s", ip_str);
            } else {
                 LOG(LOG_LEVEL_DEBUG, "Resolved IP %s to hostname %s", ip_str, resolved_hostname);
            }
        } else { // Target is potentially a hostname
             LOG(LOG_LEVEL_DEBUG, "Target '%s' identified as potential hostname", target);
             struct addrinfo hints, *res = NULL;
             memset(&hints, 0, sizeof(hints));
             hints.ai_family = AF_INET; // IPv4 only for simplicity here
             hints.ai_socktype = SOCK_DGRAM; // Or SOCK_STREAM

             int err = getaddrinfo(target, NULL, &hints, &res);
             if (err != 0 || res == NULL) {
                 LOG(LOG_LEVEL_ERROR, "Hostname resolution failed for '%s': %s", target, gai_strerror(err));
                 return; // Cannot proceed without IP
             }
             // Get the first IP address found
             struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;
             inet_ntop(AF_INET, &(addr->sin_addr), ip_str, sizeof(ip_str));
             freeaddrinfo(res);
             safe_strlcpy(resolved_hostname, target, sizeof(resolved_hostname), "process_target: target_is_hostname");
             LOG(LOG_LEVEL_INFO, "Resolved hostname '%s' to IP %s", resolved_hostname, ip_str);
        }

        // --- Resolve MAC using IP/Hostname (Check Cache First) ---
        arp_cache_entry *entry = find_arp_cache_entry(ip_str, resolved_hostname);
        if (entry != NULL) {
            safe_strlcpy(mac_str, entry->mac, sizeof(mac_str), "process_target: cache_mac");
            LOG(LOG_LEVEL_INFO, "Using cached MAC %s for %s (%s)", mac_str, ip_str, resolved_hostname);
        } else {
            LOG(LOG_LEVEL_INFO, "MAC not found in cache for %s (%s). Performing ARP resolution...", ip_str, resolved_hostname);
#ifdef _WIN32
            if (get_mac_from_ip(ip_str, resolved_mac_bytes) != 0)
#else
            if (get_mac_from_ip(ip_str, cfg->iface, resolved_mac_bytes) != 0)
#endif
            {
                LOG(LOG_LEVEL_ERROR, "ARP resolution failed for %s. Cannot send WoL packet.", ip_str);
                return; // Cannot proceed without MAC
            } else {
                // Format resolved MAC bytes into string
                safe_snprintf(mac_str, sizeof(mac_str), "process_target resolved mac format", "%02X:%02X:%02X:%02X:%02X:%02X",
                              resolved_mac_bytes[0], resolved_mac_bytes[1], resolved_mac_bytes[2],
                              resolved_mac_bytes[3], resolved_mac_bytes[4], resolved_mac_bytes[5]);
                LOG(LOG_LEVEL_INFO, "ARP resolved %s to MAC %s", ip_str, mac_str);
                // Update cache with the new information
                update_arp_cache_entry(ip_str, resolved_hostname, mac_str);
            }
        }
    } // End if (!mac_provided_directly)

    // --- Send WoL Packet ---
    if (mac_str[0] == '\0') {
        LOG(LOG_LEVEL_ERROR, "Could not determine MAC address for target '%s'. Skipping WoL.", target);
        return;
    }
    metric_wakeup_attempts++;
    send_wol_packet(mac_str, cfg->broadcast_ip);

    // --- Attempt Reverse ARP/Confirmation (Optional) ---
    LOG(LOG_LEVEL_INFO, "Waiting a few seconds before checking reverse ARP...");
    msleep(5000); // Wait for machine to potentially boot and get IP

    char new_ip[64] = "";
    int rev_arp_success = 0;
    int attempts = 3; // Try a few times
    while (attempts-- > 0) {
#ifdef _WIN32
        if (get_ip_from_mac_rev(mac_str, new_ip, sizeof(new_ip)) == 0)
#else
        if (get_ip_from_mac_rev(mac_str, new_ip, sizeof(new_ip), cfg->iface) == 0) // Pass interface for Linux version
#endif
        {
             rev_arp_success = 1;
             break;
        }
        if (attempts > 0) msleep(2000); // Wait between attempts
    }


    if (rev_arp_success) {
        char new_hostname[128] = "-";
        struct sockaddr_in sa_rev;
        memset(&sa_rev, 0, sizeof(sa_rev));
        sa_rev.sin_family = AF_INET;
        // Try reverse DNS on the found IP
        if (inet_pton(AF_INET, new_ip, &sa_rev.sin_addr) == 1) {
             if (getnameinfo((struct sockaddr *)&sa_rev, sizeof(sa_rev), new_hostname, sizeof(new_hostname), NULL, 0, NI_NAMEREQD) != 0) {
                 // Keep default "-" if lookup fails
             }
        }
        LOG(LOG_LEVEL_INFO, "Reverse ARP successful: MAC %s now has IP %s (%s)", mac_str, new_ip, new_hostname);
        metric_wol_success_total++; // Count as success if reverse ARP finds IP
        // Update cache with potentially new IP/hostname for this MAC
        update_arp_cache_entry(new_ip, new_hostname, mac_str);
    } else {
        LOG(LOG_LEVEL_INFO, "Reverse ARP failed or timed out for MAC %s.", mac_str);
        // WoL packet was sent, but confirmation failed. Might still have worked.
    }
}


/* --------------------- Main --------------------- */
int main(int argc, char *argv[]) {
    config_t cfg;
    init_config(&cfg); // Initialize default config

    const char *target_arg = parse_arguments(argc, argv, &cfg); // Parse command line
    if (!target_arg) {
        // Usage printed by parse_arguments on error or help request
        exit(EXIT_FAILURE);
    }

    // --- Platform Initialization ---
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed. Exiting.\n");
        exit(EXIT_FAILURE);
    }
#endif

    // --- Subsystem Initialization ---
    logger_init(&cfg, argv[0]); // Start logger first
    arp_cache_init();           // Init ARP cache structures
    metrics_init();             // Start metrics server thread

    // --- Network Setup ---
    auto_detect_interface(&cfg); // Auto-detect interface if needed

    // --- Load ARP Cache ---
    load_arp_cache_from_file(cfg.cache_filename);

    // --- Process Target(s) ---
    // Check if target_arg is a file or a single target
    FILE *fp = fopen(target_arg, "r");
    if (fp != NULL) { // Argument is a file
        LOG(LOG_LEVEL_INFO, "Processing target list file: %s", target_arg);
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            // Remove trailing newline/carriage return
            line[strcspn(line, "\r\n")] = 0;
            // Skip empty lines or comments (e.g., starting with #)
            if (line[0] == '\0' || line[0] == '#') continue;
            process_target(line, &cfg);
        }
        fclose(fp);
    } else { // Argument is a single target
        process_target(target_arg, &cfg);
    }

    // --- Flush ARP Cache & Shutdown ---
    flush_arp_cache_to_file(cfg.cache_filename);
    arp_cache_destroy();    // Free ARP cache memory
    metrics_shutdown();     // Signal metrics server to stop (optional)
    logger_close();         // Flush logs and shut down logger thread

#ifdef _WIN32
    WSACleanup(); // Cleanup Winsock
#endif

    return EXIT_SUCCESS;
}