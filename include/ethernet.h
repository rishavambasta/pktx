#ifndef PKTX_ETHERNET_H
#define PKTX_ETHERNET_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "payload.h"

#define ETHER_HDR_LEN 14
#define ETHER_TYPE_IPV4 0x0800
#define ETHER_TYPE_ARP  0x0806
#define ETHER_TYPE_IPV6 0x86DD

#pragma pack(push, 1)
typedef struct {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ethertype; // Network byte order
} eth_hdr_t;
#pragma pack(pop)

typedef struct {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;
    uint32_t total_length; // 64 to 1514 bytes
    payload_type_t payload_type;
} eth_config_t;

// Set default Ethernet configuration values
void eth_config_set_defaults(eth_config_t *cfg);

// Build complete L2 Ethernet packet into buffer. Returns packet total size in bytes or 0 on failure.
size_t build_ethernet_packet(const eth_config_t *cfg, uint8_t *buffer, size_t max_buf_len);

// Parse raw Ethernet frame into eth_hdr_t and extract payload pointer/len
bool parse_ethernet_header(const uint8_t *buffer, size_t buf_len, eth_hdr_t *hdr_out, const uint8_t **payload_out, size_t *payload_len_out);

// Display parsed Ethernet frame summary
void print_ethernet_header(const eth_hdr_t *hdr, size_t total_len);

#endif // PKTX_ETHERNET_H
