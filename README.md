# Wakey

Wakey is a cross–platform utility that sends Wake-on-LAN (WoL) magic packets to remote devices while providing advanced network and diagnostic capabilities. It features asynchronous logging with log rotation and optional remote logging, safe string operations to guard against buffer overflows, ARP resolution with caching, and a lightweight HTTP endpoint to export operational metrics in Prometheus format.

---

## Table of Contents

- [Features](#features)
- [Functional Modules](#functional-modules)
  - [Asynchronous Logging](#asynchronous-logging)
  - [Safe String Wrappers](#safe-string-wrappers)
  - [Metrics and Instrumentation](#metrics-and-instrumentation)
  - [ARP Cache](#arp-cache)
  - [Network Interface Auto-Detection](#network-interface-auto-detection)
  - [Wake-on-LAN Implementation](#wake-on-lan-implementation)
  - [ARP and Reverse ARP Resolution](#arp-and-reverse-arp-resolution)
- [Command-Line Options](#command-line-options)
- [Usage Examples](#usage-examples)
- [Compilation and Configuration](#compilation-and-configuration)
- [Application Workflow](#application-workflow)
- [Future Enhancements](#future-enhancements)

---

## Features

- **Asynchronous and Buffered Logging:**  
  - All log messages are enqueued and processed by a dedicated logging thread.
  - Logs are stamped with a timestamp, log level, and context information (e.g., source file, line number, function name).
  - When compiling with `-DDEBUG`, additional context (and even a stack trace on errors if compiled with `-DENABLE_STACKTRACE` on POSIX systems) is included.
  - Supports log rotation based on maximum file size (default 1MB) or fixed time intervals (default daily). Rotated logs are renamed with a timestamp and automatically compressed with `gzip`.
  - If no log file is specified, logs are emitted to syslog on POSIX or to the Windows Event Log.

- **Safe String Wrappers:**  
  - Uses custom wrappers (`safe_strlcpy_wrapper` and `safe_snprintf`) instead of standard string functions, ensuring that string copies and formatted outputs do not risk buffer overflow.
  - Warnings are logged if truncation occurs.

- **Operational Metrics and Instrumentation:**  
  - Numerous counters track the number of wake-up attempts, successful wake-ups, ARP resolution attempts/failures, average ARP resolution times, and reverse ARP attempts.
  - A lightweight HTTP server runs on port 9100 by default and exports metrics in Prometheus-compatible format for easy integration with monitoring systems.

- **ARP Resolution and Caching:**  
  - When a target is given as an IP address or hostname, the application attempts to resolve the corresponding MAC address using ARP. On Windows, the native `SendARP` API is used; on POSIX systems, a raw socket and ARP request/reply mechanism is employed.
  - An in-memory ARP cache is maintained using a minimal hash table (inspired by UTHASH) and is written to disk (default file: `arp_cache.txt`) on exit. Cached entries are reused, reducing the need for repeated ARP resolution.

- **Network Interface Auto-Detection:**  
  - On POSIX systems, if the network interface is set to `"auto"`, the application scans available interfaces using `getifaddrs` and automatically selects the first non–loopback IPv4 interface.
  - On Windows, if `"auto"` is specified, a default interface name is used.

- **Wake-on-LAN (WoL) Packet Transmission:**  
  - Constructs a “magic packet” by prepending 6 bytes of `0xFF` followed by 16 repetitions of the target MAC address.
  - Sends the packet to a broadcast IP (default: `255.255.255.255`) on port 9 using UDP.

- **Reverse ARP Resolution:**  
  - After sending the WoL packet, the application attempts reverse ARP resolution—trying to determine the target’s new IP address.
  - On Windows, reverse ARP is attempted by scanning the network's ARP table; on POSIX systems, the current implementation acts as a placeholder for asynchronous netlink support.

---

## Functional Modules

### Asynchronous Logging

- **Description:**  
  Log messages from various parts of the application are enqueued and then processed asynchronously by a dedicated logging thread. Depending on the configuration, logs may be written to a file (with rotation and compression), sent using syslog (on POSIX), or sent to the Windows Event Log.

- **Key Points:**
  - Log rotation is triggered either by the log file reaching a maximum size or when a certain time interval has passed.
  - Remote logging can be enabled to forward log messages to an external log collector.

### Safe String Wrappers

- **Description:**  
  Replaces standard string operations (`strlcpy`, `snprintf`) with safer alternatives that check for possible truncation. If lost characters are detected, a warning message is logged.
  
- **Key Functions:**
  - `safe_strlcpy_wrapper()`
  - `safe_snprintf()`

### Metrics and Instrumentation

- **Description:**  
  The application tracks numerous counters and metrics including:
  - Total wake-up attempts.
  - Successful wake-up events.
  - ARP resolution attempts, failures, and latency.
  - Reverse ARP attempts and successes.
  
- **Exporting Metrics:**  
  A lightweight HTTP server running in a dedicated thread serves these metrics in a format directly consumable by Prometheus.

### ARP Cache

- **Description:**  
  ARP entries are cached to minimize repeated ARP requests. The runtime in-memory cache is maintained using a small hash table, and the entire cache is loaded from or flushed to a disk file (default: `arp_cache.txt`).

### Network Interface Auto-Detection

- **Description:**  
  If the network interface is unspecified (or set to `"auto"`), the system’s available interfaces are examined:
  - On POSIX systems, the tool chooses the first non–loopback IPv4 interface.
  - On Windows, a default value is applied if no explicit interface is provided.

### Wake-on-LAN Implementation

- **Description:**  
  Constructs and sends a WoL “magic packet” based on the provided MAC address. The packet is sent via UDP to the configured broadcast address.
  
- **Usage:**  
  Can be used by directly supplying a MAC address or by resolving the MAC from an IP address or hostname.

### ARP and Reverse ARP Resolution

- **ARP Resolution:**  
  - Resolves a target IP’s MAC using platform–specific mechanisms.
  - If resolution fails, a cached entry may be used (if available).

- **Reverse ARP:**  
  - After sending a WoL packet, the application periodically checks to see if the target device’s IP becomes available.
  - On Windows, reverse ARP is attempted by scanning the ARP table; on POSIX, the current implementation is a demonstration placeholder for asynchronous netlink support.

---

## Command-Line Options


- **\<target>**:  
  A required argument that can be one of the following:
  - **IP Address or Hostname:** The program will attempt ARP resolution to determine the MAC address.
  - **MAC Address:** In the format `XX:XX:XX:XX:XX:XX` (when no dots are present), the provided MAC address is used directly.
  - **File Name:** A path to a file where multiple targets (one per line) are provided.

---

## Usage Examples

- **Example 1: Sending a WoL Packet to an IP Address**

  ```bash
  ./wakey 192.168.1.50

  The application attempts to resolve the MAC address for 192.168.1.50 (using ARP or a cache entry) before sending the WoL packet with the default broadcast address.

- **Example 2: Specifying a Broadcast IP, Network Interface, and ARP Cache File**
  ```bash
  ./wakey -b 10.0.0.255 -i eth0 -c /path/to/arp_cache.txt 192.168.0.10
  This command sets:
  - Broadcast IP to 10.0.0.255
  - Network interface to eth0
  - Uses a custom ARP cache file located at /path/to/arp_cache.txt

- **Example 3: Logging to a File with Remote Logging Enabled**
  ```bash
  ./wakey --logfile /var/log/wakey.log --remote 192.168.1.100:514 00:1A:2B:3C:4D:5E

  Logs are directed to /var/log/wakey.log while simultaneously sending remote log messages to 192.168.1.100 on port 514. The provided target is a MAC address, used directly without ARP resolution.

- **Example 4: Processing Multiple IP-Addresses/MAC-Addresses from a File (In this case, 'targets.txt')**
  ```bash
  ./wakey targets.txt

  If targets.txt contains multiple targets (IP addresses, hostnames, or MAC addresses on separate lines), the application processes each target sequentially.

## Compilation and Configuration

- **Compilation Options:**
  - To enable extra logging (with more detailed context):
    ```bash
    gcc -DDEBUG -o wakey wakey.c -pthread
    
  - To enable stack trace generation on errors (for POSIX systems):
    ```bash
    gcc -DDEBUG -DENABLE_STACKTRACE -o wakey wakey.c -pthread

- **Cross–Platform Considerations:**
  - **POSIX Systems:** Uses pthread for threading, syslog for log messaging (if no log file is provided), and native socket APIs for network operations.
  - **Windows:** Uses Windows Critical Sections, the Windows Event Log for logging (if no log file is provided), and Winsock for network operations.

