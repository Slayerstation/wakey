#include "network.h"
#include "utils.h" // For safe_strlcpy, safe_snprintf
#include "metrics.h" // For updating metrics

/* --------------------- Network Interface Auto-Detection --------------------- */
#ifndef _WIN32
void auto_detect_interface(config_t *cfg) {
    if (strcmp(cfg->iface, "auto") != 0) return; // Only run if set to "auto"

    struct ifaddrs *ifaddr, *ifa;
    char best_iface[IFNAMSIZ] = ""; // Store the best candidate

    if (getifaddrs(&ifaddr) == -1) {
        LOG(LOG_LEVEL_WARN, "getifaddrs failed: %s. Cannot auto-detect interface.", strerror(errno));
        safe_strlcpy(cfg->iface, "eth0", sizeof(cfg->iface), "auto_detect_interface_fallback"); // Fallback guess
        LOG(LOG_LEVEL_WARN, "Falling back to interface '%s'. Please specify manually if incorrect.", cfg->iface);
        return;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;

        // Check for IPv4, UP, RUNNING, not LOOPBACK, not POINTTOPOINT
        if (ifa->ifa_addr->sa_family == AF_INET &&
            (ifa->ifa_flags & IFF_UP) &&
            (ifa->ifa_flags & IFF_RUNNING) &&
            !(ifa->ifa_flags & IFF_LOOPBACK) &&
            !(ifa->ifa_flags & IFF_POINTOPOINT))
        {
             // Basic check: prefer interfaces starting with 'e' (eth, eno, enp...)
            if (ifa->ifa_name[0] == 'e') {
                safe_strlcpy(best_iface, ifa->ifa_name, sizeof(best_iface), "auto_detect_interface_candidate");
                break; // Found a likely candidate
            } else if (best_iface[0] == '\0') {
                 // Keep the first valid one if no 'e' interface found yet
                 safe_strlcpy(best_iface, ifa->ifa_name, sizeof(best_iface), "auto_detect_interface_first");
            }
        }
    }
    freeifaddrs(ifaddr);

    if (best_iface[0] != '\0') {
         safe_strlcpy(cfg->iface, best_iface, sizeof(cfg->iface), "auto_detect_interface_final");
         LOG(LOG_LEVEL_INFO, "Auto-detected interface: %s", cfg->iface);
    } else {
        LOG(LOG_LEVEL_WARN, "Could not auto-detect a suitable network interface.");
        safe_strlcpy(cfg->iface, "eth0", sizeof(cfg->iface), "auto_detect_interface_fallback2"); // Fallback guess
        LOG(LOG_LEVEL_WARN, "Falling back to interface '%s'. Please specify manually if incorrect.", cfg->iface);
    }
}
#else // Windows - Auto-detection is less standard, often rely on default route metrics
void auto_detect_interface(config_t *cfg) {
    // On Windows, "auto" isn't implemented simply. We'll just log a message.
    // The underlying Windows functions (SendARP, GetIpNetTable) often figure out
    // the correct interface implicitly or use routing tables.
    if (strcmp(cfg->iface, "auto") == 0) {
        LOG(LOG_LEVEL_INFO, "Interface auto-detection requested on Windows. Relying on system defaults.");
        // No change needed to cfg->iface, Windows functions handle it differently.
        // We could use GetBestInterfaceEx, but it adds complexity.
        safe_strlcpy(cfg->iface, "default", sizeof(cfg->iface), "auto_detect_interface_win"); // Placeholder
    }
}
#endif

/* --------------------- Safe MAC Address Parsing --------------------- */
// Expects format XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
int parse_mac_address(const char *mac_str, unsigned char mac[MAC_SIZE]) {
    if (!mac_str || strlen(mac_str) != 17) return -1; // Quick length check

    char mac_copy[18]; // Need space for null terminator
    safe_strlcpy(mac_copy, mac_str, sizeof(mac_copy), "parse_mac_address");

    int values[MAC_SIZE];
    int i = 0;
    char *ptr = mac_copy;

    for (i = 0; i < MAC_SIZE; i++) {
        char *endptr;
        long val = strtol(ptr, &endptr, 16);
        if (endptr == ptr || val < 0 || val > 255) return -1; // Invalid hex or out of range
        values[i] = (int)val;

        if (i < MAC_SIZE - 1) {
            if (*endptr != ':' && *endptr != '-') return -1; // Invalid separator
            ptr = endptr + 1; // Move past separator
        } else {
             if (*endptr != '\0') return -1; // Should be end of string after last byte
        }
    }

    // If parsing succeeded, copy to output buffer
    for(i=0; i<MAC_SIZE; ++i) {
        mac[i] = (unsigned char)values[i];
    }
    return 0; // Success
}

/* --------------------- Wake-on-LAN Module --------------------- */
void send_wol_packet(const char *mac_address, const char *broadcast_ip) {
    unsigned char packet[MAGIC_PACKET_SIZE];
    unsigned char mac[MAC_SIZE];
    struct sockaddr_in addr;
    int sock = -1; // Initialize to invalid

    if (parse_mac_address(mac_address, mac) != 0) {
        LOG(LOG_LEVEL_ERROR, "Invalid MAC address format for WOL: %s", mac_address);
        return;
    }

    // Construct Magic Packet
    memset(packet, 0xFF, MAC_SIZE); // First 6 bytes are FF
    for (int i = 1; i < 17; i++) { // Repeat MAC 16 times (indices 6 to 101)
        memcpy(packet + (i * MAC_SIZE), mac, MAC_SIZE);
    }

    // Create UDP socket
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        LOG(LOG_LEVEL_ERROR, "WOL: Socket creation failed: %s", strerror(errno));
        return;
    }

    // Enable broadcast option
    int optval = 1;
#ifdef _WIN32
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char *)&optval, sizeof(optval)) < 0) {
        LOG(LOG_LEVEL_ERROR, "WOL: Failed to set broadcast option: %s", strerror(errno));
        CLOSESOCKET(sock); return;
    }
#else
     if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval)) < 0) {
        LOG(LOG_LEVEL_ERROR, "WOL: Failed to set broadcast option: %s", strerror(errno));
        CLOSESOCKET(sock); return;
    }
#endif

    // Set up broadcast address structure
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(DEFAULT_WOL_PORT);
    // Use inet_pton for safety
    if (inet_pton(AF_INET, broadcast_ip, &addr.sin_addr) <= 0) {
         LOG(LOG_LEVEL_ERROR, "WOL: Invalid broadcast IP address: %s", broadcast_ip);
         CLOSESOCKET(sock); return;
    }

    // Send the packet
    // Use ssize_t for the return type of sendto, now correctly defined via platform.h
    ssize_t sent_bytes = sendto(sock, (const char *)packet, sizeof(packet), 0,
                                (struct sockaddr *)&addr, sizeof(addr));

    if (sent_bytes < 0) {
        LOG(LOG_LEVEL_ERROR, "WOL: Failed to send packet to %s: %s", broadcast_ip, strerror(errno));
    } else if ((size_t)sent_bytes != sizeof(packet)) { // Cast safe after checking < 0
        LOG(LOG_LEVEL_WARN, "WOL: Sent %zd bytes, expected %d", sent_bytes, (int)sizeof(packet));
    } else {
        LOG(LOG_LEVEL_INFO, "WOL: Magic packet sent to %s (MAC: %s)", broadcast_ip, mac_address);
    }

    CLOSESOCKET(sock);
}


/* --------------------- ARP Resolution Module --------------------- */
#ifdef _WIN32
int get_mac_from_ip(const char *target_ip, unsigned char *mac) {
    LOG(LOG_LEVEL_DEBUG, "ARP: Resolving MAC for IP %s (Windows)", target_ip);
    IPAddr destIp = 0;
    if (inet_pton(AF_INET, target_ip, &destIp) != 1) { // Use inet_pton for safety
         LOG(LOG_LEVEL_ERROR, "ARP: Invalid target IP address format: %s", target_ip);
         return -1;
    }

    ULONG mac_addr[2] = {0}; // Needs 64 bits for MAC address storage
    ULONG mac_addr_len = MAC_SIZE; // Expected length is 6 bytes

    uint64_t start_time = get_current_time_ms();
    metric_arp_attempts_total++;

    DWORD ret = SendARP(destIp, 0, (PULONG)mac_addr, &mac_addr_len); // Source IP 0 lets system choose

    uint64_t end_time = get_current_time_ms();
    metric_arp_resolution_time_ms_total += (end_time - start_time);
    metric_arp_resolution_count++;

    if (ret != NO_ERROR) {
        metric_arp_failures_total++;
        LOG(LOG_LEVEL_WARN, "ARP: SendARP failed for IP %s with error %lu", target_ip, ret);
        return -1;
    }

    if (mac_addr_len != MAC_SIZE) {
        metric_arp_failures_total++; // Count as failure if length is wrong
        LOG(LOG_LEVEL_WARN, "ARP: SendARP returned MAC length %lu, expected %d for IP %s", mac_addr_len, MAC_SIZE, target_ip);
        return -1;
    }

    // Copy the MAC address (stored in lower 6 bytes of mac_addr[0] and mac_addr[1])
    // Assuming mac_addr is treated as byte array: b0,b1,b2,b3, b4,b5,b6,b7
    // MAC is typically b0:b1:b2:b3:b4:b5
    memcpy(mac, mac_addr, MAC_SIZE);
    LOG(LOG_LEVEL_DEBUG, "ARP: Resolved IP %s to MAC %02X:%02X:%02X:%02X:%02X:%02X", target_ip,
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return 0; // Success
}

#else // POSIX (Linux specific raw socket ARP)
int get_mac_from_ip(const char *target_ip, const char *iface, unsigned char *mac) {
    LOG(LOG_LEVEL_DEBUG, "ARP: Resolving MAC for IP %s on interface %s (Linux)", target_ip, iface);
    int sockfd = -1;
    int arp_sock = -1;
    struct ifreq ifr;
    unsigned char local_mac[MAC_SIZE];
    struct sockaddr_in local_ip_addr;
    struct in_addr target_ip_addr;

    metric_arp_attempts_total++;
    uint64_t start_time = get_current_time_ms();

    // --- Get local interface MAC and IP ---
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        LOG(LOG_LEVEL_ERROR, "ARP: DGRAM socket error: %s", strerror(errno));
        goto arp_fail;
    }
    memset(&ifr, 0, sizeof(ifr));
    safe_strlcpy(ifr.ifr_name, iface, IFNAMSIZ, "get_mac_from_ip_linux: ifr_name");

    // Get MAC Address
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        LOG(LOG_LEVEL_ERROR, "ARP: ioctl SIOCGIFHWADDR failed for %s: %s", iface, strerror(errno));
        CLOSESOCKET(sockfd); goto arp_fail;
    }
    memcpy(local_mac, ifr.ifr_hwaddr.sa_data, MAC_SIZE);

    // Get IP Address
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        LOG(LOG_LEVEL_ERROR, "ARP: ioctl SIOCGIFADDR failed for %s: %s", iface, strerror(errno));
        CLOSESOCKET(sockfd); goto arp_fail;
    }
    memcpy(&local_ip_addr, &ifr.ifr_addr, sizeof(struct sockaddr_in));
    CLOSESOCKET(sockfd); sockfd = -1; // Done with this socket

    // Convert target IP string
    if (inet_pton(AF_INET, target_ip, &target_ip_addr) <= 0) {
        LOG(LOG_LEVEL_ERROR, "ARP: Invalid target IP address format: %s", target_ip);
        goto arp_fail;
    }

    // --- Create Raw Packet Socket ---
    arp_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (arp_sock < 0) {
        LOG(LOG_LEVEL_ERROR, "ARP: Raw socket creation failed: %s (Are you root?)", strerror(errno));
        goto arp_fail;
    }

    // Bind socket to the specific interface
    struct sockaddr_ll sock_addr;
    memset(&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sll_family = AF_PACKET;
    sock_addr.sll_ifindex = if_nametoindex(iface); // Get interface index
    if (sock_addr.sll_ifindex == 0) {
         LOG(LOG_LEVEL_ERROR, "ARP: if_nametoindex failed for %s: %s", iface, strerror(errno));
         goto arp_fail;
    }
    sock_addr.sll_protocol = htons(ETH_P_ARP);
    // Binding optional for sending, but good practice
    // if (bind(arp_sock, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) < 0) {
    //     LOG(LOG_LEVEL_ERROR, "ARP: Raw socket bind failed: %s", strerror(errno));
    //     goto arp_fail;
    // }

    // --- Construct ARP Request Packet ---
    #pragma pack(push, 1) // Ensure struct packing
    typedef struct {
        // Ethernet Header
        uint8_t  dest_mac[6];
        uint8_t  src_mac[6];
        uint16_t ethertype;
        // ARP Payload
        uint16_t hw_type;
        uint16_t proto_type;
        uint8_t  hw_size;
        uint8_t  proto_size;
        uint16_t opcode;
        uint8_t  sender_mac[6];
        uint32_t sender_ip;
        uint8_t  target_mac[6];
        uint32_t target_ip;
    } arp_packet_t;
    #pragma pack(pop)

    arp_packet_t arp_req;
    // Ethernet Header
    memset(arp_req.dest_mac, 0xff, 6); // Broadcast MAC
    memcpy(arp_req.src_mac, local_mac, 6);
    arp_req.ethertype = htons(ETH_P_ARP);
    // ARP Payload
    arp_req.hw_type = htons(1); // Ethernet
    arp_req.proto_type = htons(ETH_P_IP); // IPv4
    arp_req.hw_size = 6;
    arp_req.proto_size = 4;
    arp_req.opcode = htons(1); // ARP Request
    memcpy(arp_req.sender_mac, local_mac, 6);
    arp_req.sender_ip = local_ip_addr.sin_addr.s_addr;
    memset(arp_req.target_mac, 0x00, 6); // Ask for this MAC
    arp_req.target_ip = target_ip_addr.s_addr;

    // --- Send ARP Request ---
    struct sockaddr_ll dest_addr; // Destination for sendto
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sll_family = AF_PACKET;
    dest_addr.sll_ifindex = sock_addr.sll_ifindex;
    dest_addr.sll_halen = ETH_ALEN; // Hardware address length
    memset(dest_addr.sll_addr, 0xff, 6); // Send to broadcast MAC

    // Use ssize_t for return type
    ssize_t sent = sendto(arp_sock, &arp_req, sizeof(arp_req), 0,
                          (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (sent != sizeof(arp_req)) {
        LOG(LOG_LEVEL_ERROR, "ARP: sendto failed or incomplete (%zd bytes): %s", sent, strerror(errno));
        goto arp_fail;
    }

    // --- Receive ARP Reply ---
    // Set timeout for receive operation
    struct timeval timeout = {2, 0}; // 2 second timeout
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(arp_sock, &fds);

    int ret = select(arp_sock + 1, &fds, NULL, NULL, &timeout);
    if (ret <= 0) {
        if (ret == 0) LOG(LOG_LEVEL_WARN, "ARP: Reply timeout for IP %s on %s", target_ip, iface);
        else LOG(LOG_LEVEL_ERROR, "ARP: select() error: %s", strerror(errno));
        goto arp_fail;
    }

    // Receive data
    unsigned char recv_buf[sizeof(arp_packet_t) + 100]; // Buffer larger than packet
    // Use ssize_t for return type
    ssize_t recv_len = recvfrom(arp_sock, recv_buf, sizeof(recv_buf), 0, NULL, NULL);
    CLOSESOCKET(arp_sock); arp_sock = -1; // Close socket after send/recv attempt

    if (recv_len <= 0) {
        LOG(LOG_LEVEL_ERROR, "ARP: recvfrom failed: %s", strerror(errno));
        goto arp_fail;
    }
    if ((size_t)recv_len < sizeof(arp_packet_t)) { // Cast safe after checking <= 0
        LOG(LOG_LEVEL_WARN, "ARP: Received runt packet (%zd bytes)", recv_len);
        goto arp_fail;
    }

    // --- Parse ARP Reply ---
    arp_packet_t *arp_reply = (arp_packet_t *)recv_buf;
    // Basic validation
    if (ntohs(arp_reply->ethertype) != ETH_P_ARP) goto arp_fail; // Not ARP
    if (ntohs(arp_reply->opcode) != 2) goto arp_fail; // Not ARP Reply
    if (arp_reply->sender_ip != target_ip_addr.s_addr) goto arp_fail; // Reply from wrong IP
    if (arp_reply->hw_size != 6 || arp_reply->proto_size != 4) goto arp_fail; // Sanity check sizes

    // Success! Copy the MAC address
    memcpy(mac, arp_reply->sender_mac, MAC_SIZE);

    uint64_t end_time = get_current_time_ms();
    metric_arp_resolution_time_ms_total += (end_time - start_time);
    metric_arp_resolution_count++;

    LOG(LOG_LEVEL_DEBUG, "ARP: Resolved IP %s to MAC %02X:%02X:%02X:%02X:%02X:%02X", target_ip,
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return 0; // Success

arp_fail:
    // Cleanup and record failure
    if (sockfd >= 0) CLOSESOCKET(sockfd);
    if (arp_sock >= 0) CLOSESOCKET(arp_sock);
    metric_arp_failures_total++;
    uint64_t end_time = get_current_time_ms(); // Measure time even on failure
    metric_arp_resolution_time_ms_total += (end_time - start_time);
    metric_arp_resolution_count++;
    return -1; // Failure
}
#endif // _WIN32 vs POSIX for get_mac_from_ip


/* --------------------- Reverse ARP Resolution Module --------------------- */
#ifdef _WIN32
int get_ip_from_mac_rev(const char *mac_str, char *ip_str, size_t ip_str_size) {
    LOG(LOG_LEVEL_DEBUG, "RevARP: Looking for IP for MAC %s (Windows)", mac_str);
    metric_reverse_arp_attempts_total++;
    unsigned char target_mac_bytes[MAC_SIZE];
    if (parse_mac_address(mac_str, target_mac_bytes) != 0) {
        LOG(LOG_LEVEL_ERROR, "RevARP: Invalid MAC address format: %s", mac_str);
        return -1;
    }

    PMIB_IPNETTABLE pIpNetTable = NULL;
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;
    int found = 0;

    // Call GetIpNetTable once to get the required buffer size
    if (GetIpNetTable(NULL, &dwSize, 0) == ERROR_INSUFFICIENT_BUFFER) {
        pIpNetTable = (MIB_IPNETTABLE*) malloc(dwSize);
        if (pIpNetTable == NULL) {
            LOG(LOG_LEVEL_ERROR, "RevARP: Memory allocation failed for GetIpNetTable buffer (%lu bytes)", dwSize);
            return -1;
        }
    } else {
        LOG(LOG_LEVEL_ERROR, "RevARP: GetIpNetTable failed getting buffer size.");
        return -1; // Failed to get size info
    }

    // Call GetIpNetTable again to get the actual data
    dwRetVal = GetIpNetTable(pIpNetTable, &dwSize, 0);
    if (dwRetVal != NO_ERROR) {
        LOG(LOG_LEVEL_ERROR, "RevARP: GetIpNetTable failed with error %lu", dwRetVal);
        free(pIpNetTable);
        return -1;
    }

    // Iterate through the table
    for (DWORD i = 0; i < pIpNetTable->dwNumEntries; i++) {
        MIB_IPNETROW row = pIpNetTable->table[i];
        // Check if MAC length is correct and matches the target
        if (row.dwPhysAddrLen == MAC_SIZE && memcmp(row.bPhysAddr, target_mac_bytes, MAC_SIZE) == 0) {
            // Found a match, convert IP address to string
            struct in_addr ip_addr;
            ip_addr.s_addr = row.dwAddr;
            // Use inet_ntop for thread safety if available, otherwise stick to inet_ntoa carefully
            // For simplicity here, we keep inet_ntoa
            const char *ip_result = inet_ntoa(ip_addr);
            if (ip_result) {
                safe_strlcpy(ip_str, ip_result, ip_str_size, "get_ip_from_mac_rev_win");
                LOG(LOG_LEVEL_INFO, "RevARP: Found IP %s for MAC %s", ip_str, mac_str);
                found = 1;
                metric_reverse_arp_success_total++;
                break; // Stop after finding the first match
            }
        }
    }

    free(pIpNetTable); // Free the allocated buffer

    if (!found) {
         LOG(LOG_LEVEL_DEBUG, "RevARP: No IP found for MAC %s in ARP table.", mac_str);
         return -1; // Not found
    }

    return 0; // Success
}

#else // POSIX - Reverse ARP is harder, often requires polling or netlink
int get_ip_from_mac_rev(const char *mac_str, char *ip_str, size_t ip_str_size, const char *ifname) {
    // This implementation uses /proc/net/arp which is Linux specific and less reliable than Netlink.
    // A Netlink implementation would be more robust but significantly more complex.
    LOG(LOG_LEVEL_DEBUG, "RevARP: Looking for IP for MAC %s (Linux /proc/net/arp)", mac_str);
    metric_reverse_arp_attempts_total++;
    FILE *arp_file = fopen("/proc/net/arp", "r");
    if (!arp_file) {
        LOG(LOG_LEVEL_ERROR, "RevARP: Cannot open /proc/net/arp: %s", strerror(errno));
        return -1;
    }

    char line[256];
    char ip_addr_str[64];
    char hw_addr_str[18];
    char device[32];
    int found = 0;

    // Read header line
    if (fgets(line, sizeof(line), arp_file) == NULL) {
        LOG(LOG_LEVEL_ERROR, "RevARP: Failed to read header from /proc/net/arp");
        fclose(arp_file);
        return -1;
    }

    // Read data lines
    while (fgets(line, sizeof(line), arp_file)) {
        // Example line: 192.168.1.1    0x1         0x2         00:1c:c0:a1:b2:c3     * eth0
        // Need to parse carefully
        int num_scanned = sscanf(line, "%63s %*s %*s %17s %*s %31s", ip_addr_str, hw_addr_str, device);

        if (num_scanned >= 2) { // Need at least IP and MAC
            // Compare the read MAC address with the target MAC address (case-insensitive)
            if (strcasecmp(hw_addr_str, mac_str) == 0) {
                // Optional: check if device matches ifname if provided
                if (ifname && ifname[0] != '\0' && strcmp(ifname, "default") != 0 && num_scanned == 3) {
                     if (strcmp(device, ifname) != 0) {
                         continue; // Match found, but on wrong interface
                     }
                }

                // Found match
                safe_strlcpy(ip_str, ip_addr_str, ip_str_size, "get_ip_from_mac_rev_linux");
                LOG(LOG_LEVEL_INFO, "RevARP: Found IP %s for MAC %s (Device: %s)", ip_str, mac_str, (num_scanned==3)?device:"?");
                found = 1;
                metric_reverse_arp_success_total++;
                break; // Stop after first match
            }
        }
    }

    fclose(arp_file);

    if (!found) {
         LOG(LOG_LEVEL_DEBUG, "RevARP: No IP found for MAC %s in /proc/net/arp.", mac_str);
         return -1;
    }

    return 0; // Success
}
#endif // _WIN32 vs POSIX for get_ip_from_mac_rev