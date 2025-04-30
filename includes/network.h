#ifndef NETWORK_H
#define NETWORK_H

#include "platform.h"
#include "config.h" // Needs config_t
#include "logger.h"

#define MAC_SIZE 6
#define MAGIC_PACKET_SIZE 102
#define DEFAULT_WOL_PORT     9

/* Network Interface Auto-Detection */
void auto_detect_interface(config_t *cfg);

/* Safe MAC Address Parsing */
int parse_mac_address(const char *mac_str, unsigned char mac[MAC_SIZE]);

/* Wake-on-LAN */
void send_wol_packet(const char *mac_address, const char *broadcast_ip);

/* ARP Resolution (get MAC from IP) */
#ifdef _WIN32
int get_mac_from_ip(const char *target_ip, unsigned char *mac);
#else
int get_mac_from_ip(const char *target_ip, const char *iface, unsigned char *mac);
#endif

/* Reverse ARP Resolution (get IP from MAC) */
#ifdef _WIN32
int get_ip_from_mac_rev(const char *mac_str, char *ip_str, size_t ip_str_size);
#else
// POSIX version might need interface name
int get_ip_from_mac_rev(const char *mac_str, char *ip_str, size_t ip_str_size, const char *ifname);
#endif

#endif // NETWORK_H