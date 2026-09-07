#ifndef PKTX_IPV4_H
#define PKTX_IPV4_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "ethernet.h"
#include "payload.h"

#define IPV4_HDR_LEN 20
#define IP_PROTO_ICMP 1
#define IP_PROTO_IGMP 2
#define IP_PROTO_TCP  6
#define IP_PROTO_UDP  17
#define IP_PROTO_RAW  255

#pragma pack(push, 1)
typedef struct {
    uint8_t  ver_ihl;       // Version (4 bits) + IHL (4 bits)
    uint8_t  tos;           // Type of Service / DSCP / ECN
    uint16_t total_len;     // Total Length (Header + Payload)
    uint16_t id;            // Identification
    uint16_t flags_offset;  // Flags (3 bits) + Fragment Offset (13 bits)
    uint8_t  ttl;           // Time to Live
    uint8_t  protocol;      // Protocol (UDP, TCP, ICMP, etc.)
    uint16_t checksum;      // Header Checksum
    uint32_t src_ip;        // Source IP Address (Network Byte Order)
    uint32_t dst_ip;        // Destination IP Address (Network Byte Order)
} ipv4_hdr_t;
#pragma pack(pop)

typedef struct {
    // L2 Ethernet fields
    uint8_t src_mac[6];
    uint8_t dst_mac[6];

    // L3 IPv4 fields
    uint8_t tos;
    uint16_t id;
    bool dont_fragment;
    bool more_fragments;
    uint16_t frag_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint32_t src_ip; // Network byte order
    uint32_t dst_ip; // Network byte order
    bool auto_checksum;
    uint16_t custom_checksum;

    // Overall packet settings
    uint32_t total_length; // Total frame length: 64 to 1514 bytes
    payload_type_t payload_type;
    char payload_file_path[256];
} ipv4_config_t;

// Set default IPv4 packet configuration
void ipv4_config_set_defaults(ipv4_config_t *cfg);

// Build complete L3 Ethernet+IPv4 packet into buffer. Returns total size in bytes or 0 on failure.
size_t build_ipv4_packet(const ipv4_config_t *cfg, uint8_t *buffer, size_t max_buf_len);

// Parse raw packet for IPv4 header inside Ethernet frame
bool parse_ipv4_header(const uint8_t *buffer, size_t buf_len, ipv4_hdr_t *hdr_out, const uint8_t **payload_out, size_t *payload_len_out);

// Display parsed IPv4 header summary
void print_ipv4_header(const ipv4_hdr_t *hdr);

#endif // PKTX_IPV4_H
