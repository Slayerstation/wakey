#ifndef PLATFORM_H
#define PLATFORM_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <limits.h>
#include <sys/stat.h>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <iphlpapi.h>
  #include <windows.h>
  #include <io.h>
  #include <fcntl.h>
  #pragma comment(lib, "Ws2_32.lib")
  #pragma comment(lib, "Iphlpapi.lib")

  #define CLOSESOCKET(s) closesocket(s)
  #define LOCK_T CRITICAL_SECTION
  #define COND_T CONDITION_VARIABLE
  #define THREAD_T HANDLE
  #define THREAD_RET_T DWORD WINAPI
  #define LOCK_INIT(l) InitializeCriticalSection(l)
  #define LOCK_DESTROY(l) DeleteCriticalSection(l)
  #define LOCK(l) EnterCriticalSection(l)
  #define UNLOCK(l) LeaveCriticalSection(l)
  #define COND_INIT(c) InitializeConditionVariable(c)
  #define COND_WAIT(c, l) SleepConditionVariableCS(c, l, INFINITE)
  #define COND_SIGNAL(c) WakeConditionVariable(c)
  #define THREAD_CREATE(t, f, a) *(t) = CreateThread(NULL, 0, f, a, 0, NULL)
  #define THREAD_JOIN(t) WaitForSingleObject(t, INFINITE)
  #define THREAD_DETACH(t) CloseHandle(t) // Detach not directly needed as join is used

#else // POSIX
  #define _GNU_SOURCE
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <sys/file.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  #include <sys/ioctl.h>
  #include <net/if.h>
  #include <netdb.h>
  #include <netpacket/packet.h>
  #include <net/ethernet.h>
  #include <ifaddrs.h>
  #include <fcntl.h>
  #include <syslog.h>
  #include <pthread.h>
  #include <execinfo.h>
  #include <sys/time.h>
  #include <linux/netlink.h>
  #include <linux/rtnetlink.h>
  #include <linux/neighbour.h>

  #define CLOSESOCKET(s) close(s)
  #define LOCK_T pthread_mutex_t
  #define COND_T pthread_cond_t
  #define THREAD_T pthread_t
  #define THREAD_RET_T void*
  #define LOCK_INIT(l) pthread_mutex_init(l, NULL)
  #define LOCK_DESTROY(l) pthread_mutex_destroy(l)
  #define LOCK(l) pthread_mutex_lock(l)
  #define UNLOCK(l) pthread_mutex_unlock(l)
  #define COND_INIT(c) pthread_cond_init(c, NULL)
  #define COND_WAIT(c, l) pthread_cond_wait(c, l)
  #define COND_SIGNAL(c) pthread_cond_signal(c)
  #define THREAD_CREATE(t, f, a) pthread_create(t, NULL, f, a)
  #define THREAD_JOIN(t) pthread_join(t, NULL)
  #define THREAD_DETACH(t) pthread_detach(t)

#endif

#endif // PLATFORM_H