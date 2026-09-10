#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#ifndef strcasecmp
#define strcasecmp _stricmp
#endif
#else
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#endif

bool parse_mac_address(const char *str, uint8_t mac[6]) {
    if (!str || !mac) return false;
    unsigned int values[6];
    int i;

    // Support AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF
    if (sscanf(str, "%x:%x:%x:%x:%x:%x",
               &values[0], &values[1], &values[2],
               &values[3], &values[4], &values[5]) == 6 ||
        sscanf(str, "%x-%x-%x-%x-%x-%x",
               &values[0], &values[1], &values[2],
               &values[3], &values[4], &values[5]) == 6) {
        for (i = 0; i < 6; i++) {
            if (values[i] > 0xFF) return false;
            mac[i] = (uint8_t)values[i];
        }
        return true;
    }
    return false;
}

void format_mac_address(const uint8_t mac[6], char *buf, size_t buf_len) {
    if (!mac || !buf || buf_len < 18) return;
    snprintf(buf, buf_len, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

bool parse_ipv4_address(const char *str, uint32_t *ip_out) {
    if (!str || !ip_out) return false;
    struct in_addr addr;
    if (inet_pton(AF_INET, str, &addr) == 1) {
        *ip_out = addr.s_addr; // Network byte order
        return true;
    }
    return false;
}

void format_ipv4_address(uint32_t ip, char *buf, size_t buf_len) {
    if (!buf || buf_len < 16) return;
    struct in_addr addr;
    addr.s_addr = ip;
    inet_ntop(AF_INET, &addr, buf, buf_len);
}

uint16_t compute_checksum(const void *data, size_t len) {
    const uint16_t *ptr = (const uint16_t *)data;
    uint32_t sum = 0;

    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }

    if (len == 1) {
        sum += *(const uint8_t *)ptr;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

void print_hex_dump(const char *title, const uint8_t *data, size_t len) {
    if (title) {
        printf("--- %s (%zu bytes) ---\n", title, len);
    }
    for (size_t i = 0; i < len; i += 16) {
        printf("%04zx  ", i);
        // Print hex bytes
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len) {
                printf("%02x ", data[i + j]);
            } else {
                printf("   ");
            }
        }
        printf(" |");
        // Print ASCII characters
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len) {
                uint8_t c = data[i + j];
                printf("%c", (c >= 32 && c <= 126) ? c : '.');
            }
        }
        printf("|\n");
    }
}

bool parse_uint(const char *str, uint32_t min, uint32_t max, uint32_t *val_out) {
    if (!str || !val_out || *str == '\0') return false;
    char *endptr = NULL;
    unsigned long val = strtoul(str, &endptr, 10);
    if (*endptr != '\0') return false;
    if (val < min || val > max) return false;
    *val_out = (uint32_t)val;
    return true;
}

bool parse_u64(const char *str, uint64_t min, uint64_t max, uint64_t *val_out) {
    if (!str || !val_out || *str == '\0') return false;
    char *endptr = NULL;
    errno = 0;
    unsigned long long val = strtoull(str, &endptr, 10);
    if (errno != 0 || *endptr != '\0') return false;
    if ((uint64_t)val < min || (uint64_t)val > max) return false;
    *val_out = (uint64_t)val;
    return true;
}

bool parse_hex16(const char *str, uint16_t *val_out) {
    if (!str || !val_out || *str == '\0') return false;
    char *endptr = NULL;
    int base = 10;
    if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
        base = 16;
    } else if (isxdigit(str[0])) {
        base = 16;
    }
    unsigned long val = strtoul(str, &endptr, base);
    if (*endptr != '\0') return false;
    if (val > 0xFFFF) return false;
    *val_out = (uint16_t)val;
    return true;
}

void sleep_ms(uint32_t ms) {
    if (ms == 0) return;
#ifdef _WIN32
    Sleep((DWORD)ms);
#else
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
#endif
}

void ensure_strm_extension(char *filename, size_t max_len) {
    if (!filename || max_len == 0) return;
    size_t len = strlen(filename);
    if (len == 0) return;

    if (len < 5 || strcasecmp(filename + len - 5, ".strm") != 0) {
        if (len + 5 < max_len) {
            strcat(filename, ".strm");
        }
    }
}
