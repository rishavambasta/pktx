#ifndef PKTX_UTILS_H
#define PKTX_UTILS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define PKTX_MIN_PACKET_SIZE 64
#define PKTX_MAX_PACKET_SIZE 1514

// Utility function declarations

// Parse MAC address string "AA:BB:CC:DD:EE:FF" or "AA-BB-CC-DD-EE-FF" into 6-byte array
bool parse_mac_address(const char *str, uint8_t mac[6]);

// Format 6-byte MAC address to string "AA:BB:CC:DD:EE:FF"
void format_mac_address(const uint8_t mac[6], char *buf, size_t buf_len);

// Parse IPv4 address string "192.168.1.1" into uint32_t (in network byte order)
bool parse_ipv4_address(const char *str, uint32_t *ip_out);

// Format uint32_t IPv4 address (network byte order) to string "192.168.1.1"
void format_ipv4_address(uint32_t ip, char *buf, size_t buf_len);

// Compute 16-bit Internet Checksum (RFC 1071)
uint16_t compute_checksum(const void *data, size_t len);

// Print formatted hex dump of buffer
void print_hex_dump(const char *title, const uint8_t *data, size_t len);

// Validate generic unsigned integer input string within [min, max]
bool parse_uint(const char *str, uint32_t min, uint32_t max, uint32_t *val_out);

// Validate hex integer input string (e.g. 0x0800 or 0800) within [min, max]
bool parse_hex16(const char *str, uint16_t *val_out);

// Sleep helper for milliseconds
void sleep_ms(uint32_t ms);

// Ensure filename has .strm extension (automatically appends .strm if absent)
void ensure_strm_extension(char *filename, size_t max_len);

#endif // PKTX_UTILS_H
