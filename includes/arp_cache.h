#ifndef ARP_CACHE_H
#define ARP_CACHE_H

#include "platform.h"
#include "logger.h"

// Simplified uthash dependency (only needs HASH_FIND_STR, HASH_ADD_STR, HASH_ITER)
// Forward declare the entry struct for UT_hash_handle
struct arp_cache_entry;

struct UT_hash_handle {
    struct arp_cache_entry *next;
    unsigned hashv;
};

typedef struct arp_cache_entry {
    char ip[64];
    char hostname[128]; // Hostname might be useful
    char mac[18]; // MAC as string XX:XX:XX:XX:XX:XX
    struct UT_hash_handle hh; // Makes this struct hashable
} arp_cache_entry;

/* ARP Cache Management */
void arp_cache_init(void);
void arp_cache_destroy(void);
void load_arp_cache_from_file(const char *filename);
void flush_arp_cache_to_file(const char *filename);
arp_cache_entry* find_arp_cache_entry(const char *ip, const char *hostname); // Find by IP or hostname
void update_arp_cache_entry(const char *ip, const char *hostname, const char *mac);

#endif // ARP_CACHE_H