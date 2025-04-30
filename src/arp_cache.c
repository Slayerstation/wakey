#include "arp_cache.h"
#include "utils.h" // For safe_strlcpy

/* Minimal uthash definitions needed */
#define uthash_malloc(sz) malloc(sz)
#define uthash_free(ptr,sz) free(ptr)

// Custom HASH_FIND_STR focusing on IP as primary key
#define HASH_FIND_IP(head,findip,out)                                   \
    do {                                                                \
        out = NULL;                                                     \
        if (head && findip && findip[0] != '\0') {                      \
            unsigned _hf_hashv = 0;                                     \
            for (const char *_hf_ptr = (findip); *_hf_ptr; _hf_ptr++) { \
                _hf_hashv = _hf_hashv * 33 + (unsigned char)*_hf_ptr;   \
            }                                                           \
            for (out = head; out; out = out->hh.next) {                 \
                unsigned _hf_tmp = 0;                                   \
                for (const char *_hf_ptr = out->ip; *_hf_ptr; _hf_ptr++) {\
                    _hf_tmp = _hf_tmp * 33 + (unsigned char)*_hf_ptr;   \
                }                                                       \
                if (_hf_tmp == _hf_hashv && strcmp(out->ip, findip)==0) break; \
            }                                                           \
        }                                                               \
    } while (0)

// Custom HASH_FIND_STR focusing on Hostname as secondary key
#define HASH_FIND_HOSTNAME(head,findhost,out)                           \
    do {                                                                \
        out = NULL;                                                     \
        if (head && findhost && findhost[0] != '\0' && strcmp(findhost,"-") != 0) { \
            for (out = head; out; out = out->hh.next) {                 \
                if (strcmp(out->hostname, findhost)==0) break;          \
            }                                                           \
        }                                                               \
    } while (0)

#define HASH_ADD_STR(head, ipfield, add)                                \
    do {                                                                \
        unsigned _ha_hashv = 0;                                         \
        for (const char *_ha_ptr = (add)->ipfield; *_ha_ptr; _ha_ptr++) {\
            _ha_hashv = _ha_hashv * 33 + (unsigned char)*_ha_ptr;       \
        }                                                               \
        (add)->hh.hashv = _ha_hashv;                                    \
        (add)->hh.next = head;                                          \
        head = add;                                                     \
    } while(0)

#define HASH_ITER(hh, head, el, tmp)                                    \
    for((el)=(head), (tmp)=(el)?(el)->hh.next:NULL; el; (el)=(tmp), (tmp)=(el)?(el)->hh.next:NULL)

#define HASH_DEL(head,delptr)                                           \
    do{                                                                 \
        struct arp_cache_entry * _hd_pri = NULL;                        \
        if(head == delptr) head = delptr->hh.next;                      \
        else {                                                          \
            for(_hd_pri=head; _hd_pri->hh.next != delptr; _hd_pri=_hd_pri->hh.next); \
            _hd_pri->hh.next = delptr->hh.next;                         \
        }                                                               \
    } while(0)


/* ARP Cache Global State */
static arp_cache_entry *g_arp_cache = NULL;
static LOCK_T g_arp_cache_mutex;

/* File Locking Helpers */
#ifdef _WIN32
static int lock_file_win(HANDLE hFile, int exclusive) {
    OVERLAPPED overlapped = {0};
    DWORD flags = LOCKFILE_FAIL_IMMEDIATELY | (exclusive ? LOCKFILE_EXCLUSIVE_LOCK : 0);
    return LockFileEx(hFile, flags, 0, 0xFFFFFFFF, 0xFFFFFFFF, &overlapped); // Non-blocking attempt
}
static int unlock_file_win(HANDLE hFile) {
    OVERLAPPED overlapped = {0};
    return UnlockFileEx(hFile, 0, 0xFFFFFFFF, 0xFFFFFFFF, &overlapped);
}
#else // POSIX
static int lock_file_fd(int fd, int exclusive) {
    int op = exclusive ? LOCK_EX : LOCK_SH;
    return flock(fd, op | LOCK_NB); // Non-blocking attempt
}
static int unlock_file_fd(int fd) {
    return flock(fd, LOCK_UN);
}
#endif

void arp_cache_init(void) {
    LOCK_INIT(&g_arp_cache_mutex);
    g_arp_cache = NULL;
}

void arp_cache_destroy(void) {
    arp_cache_entry *entry, *tmp;
    LOCK(&g_arp_cache_mutex);
    HASH_ITER(hh, g_arp_cache, entry, tmp) {
        HASH_DEL(g_arp_cache, entry);
        free(entry);
    }
    g_arp_cache = NULL; // Ensure cache is marked empty
    UNLOCK(&g_arp_cache_mutex);
    LOCK_DESTROY(&g_arp_cache_mutex);
}

// Internal find function (assumes lock is held)
static arp_cache_entry* find_arp_cache_entry_locked(const char *ip, const char *hostname) {
    arp_cache_entry *entry = NULL;
    // Prioritize finding by IP if provided
    if (ip && ip[0] != '\0') {
        HASH_FIND_IP(g_arp_cache, ip, entry);
        if (entry) return entry;
    }
    // If not found by IP or IP not provided, try hostname (if provided and not "-")
    if (!entry && hostname && hostname[0] != '\0' && strcmp(hostname, "-") != 0) {
         HASH_FIND_HOSTNAME(g_arp_cache, hostname, entry);
    }
    return entry;
}

// Public find function (acquires lock)
arp_cache_entry* find_arp_cache_entry(const char *ip, const char *hostname) {
    arp_cache_entry *result;
    LOCK(&g_arp_cache_mutex);
    result = find_arp_cache_entry_locked(ip, hostname);
    UNLOCK(&g_arp_cache_mutex);
    return result; // Returns NULL if not found
}

void load_arp_cache_from_file(const char *filename) {
    FILE *fp = NULL;
    int fd = -1;
#ifdef _WIN32
    HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        if (GetLastError() != ERROR_FILE_NOT_FOUND) {
            LOG(LOG_LEVEL_WARN, "ARP Cache: Error opening file '%s' for reading: %lu", filename, GetLastError());
        } else {
             LOG(LOG_LEVEL_INFO, "ARP Cache: No cache file '%s' found.", filename);
        }
        return;
    }
    // Try to get a shared lock (non-blocking)
    if (!lock_file_win(hFile, 0)) { // 0 for shared lock
         LOG(LOG_LEVEL_WARN, "ARP Cache: Failed to lock file '%s' for reading (already locked?).", filename);
         CloseHandle(hFile);
         return;
    }
    fd = _open_osfhandle((intptr_t)hFile, _O_RDONLY);
    if (fd != -1) fp = _fdopen(fd, "r"); else CloseHandle(hFile); // Close handle if fdopen fails
#else // POSIX
    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        if (errno != ENOENT) {
            LOG(LOG_LEVEL_WARN, "ARP Cache: Error opening file '%s' for reading: %s", filename, strerror(errno));
        } else {
             LOG(LOG_LEVEL_INFO, "ARP Cache: No cache file '%s' found.", filename);
        }
        return;
    }
    // Try to get a shared lock (non-blocking)
    if (lock_file_fd(fd, 0) < 0) { // 0 for shared lock
        LOG(LOG_LEVEL_WARN, "ARP Cache: Failed to lock file '%s' for reading (already locked?): %s", filename, strerror(errno));
        close(fd);
        return;
    }
    fp = fdopen(fd, "r"); if (!fp) close(fd); // Close fd if fdopen fails
#endif

    if (!fp) {
        LOG(LOG_LEVEL_WARN, "ARP Cache: Unable to associate FILE* with file descriptor for '%s'.", filename);
        // Unlock is tricky here as we might not have fd or hFile
        return;
    }

    LOG(LOG_LEVEL_DEBUG, "ARP Cache: Loading from file '%s'", filename);
    char line[256];
    int count = 0;
    while (fgets(line, sizeof(line), fp)) {
        char file_hostname[128], file_ip[64], file_mac[18];
        // Use sscanf carefully, ensure fields are read correctly
        if (sscanf(line, "%127s %63s %17s", file_hostname, file_ip, file_mac) == 3) {
            // Basic validation
            if (strlen(file_hostname) > 0 && strlen(file_ip) > 0 && strlen(file_mac) == 17) {
                update_arp_cache_entry(file_ip, file_hostname, file_mac); // Use update to avoid duplicates
                count++;
            } else {
                 LOG(LOG_LEVEL_WARN, "ARP Cache: Skipping invalid line in cache file: %s", line);
            }
        }
    }

    fclose(fp); // This also closes the underlying fd on POSIX, but not the HANDLE on Windows

#ifdef _WIN32
    unlock_file_win(hFile);
    CloseHandle(hFile); // Explicitly close the handle
#else
    // fd is closed by fclose, just unlock
    unlock_file_fd(fd);
    // close(fd) is done implicitly by fclose(fp)
#endif
     LOG(LOG_LEVEL_DEBUG, "ARP Cache: Loaded %d entries from '%s'.", count, filename);
}


void flush_arp_cache_to_file(const char *filename) {
    FILE *fp = NULL;
    int fd = -1;
#ifdef _WIN32
    HANDLE hFile = CreateFileA(filename, GENERIC_WRITE, 0, NULL, // No sharing for exclusive write
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LOG(LOG_LEVEL_ERROR, "ARP Cache: Unable to open file '%s' for writing: %lu", filename, GetLastError());
        return;
    }
     // Try to get an exclusive lock (non-blocking)
    if (!lock_file_win(hFile, 1)) { // 1 for exclusive lock
         LOG(LOG_LEVEL_WARN, "ARP Cache: Failed to lock file '%s' for writing (already locked?).", filename);
         CloseHandle(hFile);
         return;
    }
    fd = _open_osfhandle((intptr_t)hFile, _O_WRONLY | _O_TRUNC);
    if (fd != -1) fp = _fdopen(fd, "w"); else CloseHandle(hFile);
#else // POSIX
    fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        LOG(LOG_LEVEL_ERROR, "ARP Cache: Unable to open file '%s' for writing: %s", filename, strerror(errno));
        return;
    }
    // Try to get an exclusive lock (non-blocking)
    if (lock_file_fd(fd, 1) < 0) { // 1 for exclusive lock
        LOG(LOG_LEVEL_WARN, "ARP Cache: Failed to lock file '%s' for writing (already locked?): %s", filename, strerror(errno));
        close(fd);
        return;
    }
    fp = fdopen(fd, "w"); if (!fp) close(fd);
#endif

    if (!fp) {
        LOG(LOG_LEVEL_ERROR, "ARP Cache: Unable to associate FILE* for writing '%s'.", filename);
        // Need to unlock and close handles/fds properly
#ifdef _WIN32
        unlock_file_win(hFile); CloseHandle(hFile);
#else
        unlock_file_fd(fd); close(fd);
#endif
        return;
    }

    LOG(LOG_LEVEL_DEBUG, "ARP Cache: Flushing to file '%s'", filename);
    int count = 0;
    LOCK(&g_arp_cache_mutex);
    arp_cache_entry *entry, *tmp;
    HASH_ITER(hh, g_arp_cache, entry, tmp) {
        fprintf(fp, "%s %s %s\n", entry->hostname, entry->ip, entry->mac);
        count++;
    }
    UNLOCK(&g_arp_cache_mutex);

    fflush(fp);
    fclose(fp); // Closes fd on POSIX

#ifdef _WIN32
    unlock_file_win(hFile);
    CloseHandle(hFile);
#else
    // fd closed by fclose, just unlock
    unlock_file_fd(fd);
#endif
    LOG(LOG_LEVEL_DEBUG, "ARP Cache: Flushed %d entries to '%s'.", count, filename);
}


void update_arp_cache_entry(const char *ip, const char *hostname, const char *mac) {
    if (!ip || ip[0] == '\0' || !mac || strlen(mac) != 17) {
        LOG(LOG_LEVEL_WARN, "ARP Cache: Invalid parameters for update_arp_cache_entry (IP: %s, MAC: %s)", ip ? ip : "null", mac ? mac : "null");
        return;
    }
    // Use a default hostname if none provided
    const char* effective_hostname = (hostname && hostname[0] != '\0') ? hostname : "-";

    LOCK(&g_arp_cache_mutex);
    arp_cache_entry *entry = find_arp_cache_entry_locked(ip, effective_hostname);

    if (entry) { // Entry exists, update MAC and potentially hostname
        LOG(LOG_LEVEL_DEBUG, "ARP Cache: Updating entry IP=%s", ip);
        safe_strlcpy(entry->mac, mac, sizeof(entry->mac), "update_arp_cache: mac");
        // Update hostname only if the new one is valid and different from existing one (and not "-")
        if (strcmp(effective_hostname, "-") != 0 && strcmp(entry->hostname, effective_hostname) != 0) {
             safe_strlcpy(entry->hostname, effective_hostname, sizeof(entry->hostname), "update_arp_cache: hostname");
        }
    } else { // New entry
        LOG(LOG_LEVEL_DEBUG, "ARP Cache: Adding new entry IP=%s", ip);
        entry = malloc(sizeof(arp_cache_entry));
        if (!entry) {
            LOG(LOG_LEVEL_ERROR, "ARP Cache: Failed to allocate memory for new entry.");
            UNLOCK(&g_arp_cache_mutex);
            return;
        }
        safe_strlcpy(entry->ip, ip, sizeof(entry->ip), "update_arp_cache: new ip");
        safe_strlcpy(entry->hostname, effective_hostname, sizeof(entry->hostname), "update_arp_cache: new hostname");
        safe_strlcpy(entry->mac, mac, sizeof(entry->mac), "update_arp_cache: new mac");
        HASH_ADD_STR(g_arp_cache, ip, entry); // Add based on IP field
    }
    UNLOCK(&g_arp_cache_mutex);
}