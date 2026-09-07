#ifndef PKTX_ARP_H
#define PKTX_ARP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "ethernet.h"
#include "payload.h"

#define ARP_HDR_LEN 28
#define ARP_HTYPE_ETHERNET 1
#define ARP_PTYPE_IPV4     0x0800

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY   2

#pragma pack(push, 1)
typedef struct {
    uint16_t htype;        // Hardware type (1 = Ethernet)
    uint16_t ptype;        // Protocol type (0x0800 = IPv4)
    uint8_t  hlen;         // Hardware length (6)
    uint8_t  plen;         // Protocol length (4)
    uint16_t opcode;       // Opcode (1 = Request, 2 = Reply)
    uint8_t  sender_mac[6];// Sender MAC address
    uint32_t sender_ip;    // Sender IPv4 address (Network Byte Order)
    uint8_t  target_mac[6];// Target MAC address
    uint32_t target_ip;    // Target IPv4 address (Network Byte Order)
} arp_hdr_t;
#pragma pack(pop)

typedef struct {
    // L2 Ethernet fields
    uint8_t src_mac[6];
    uint8_t dst_mac[6];

    // ARP fields
    uint16_t htype;
    uint16_t ptype;
    uint8_t  hlen;
    uint8_t  plen;
    uint16_t opcode;       // 1 = Request, 2 = Reply
    uint8_t  sender_mac[6];
    uint32_t sender_ip;    // Network byte order
    uint8_t  target_mac[6];
    uint32_t target_ip;    // Network byte order

    // Frame size & padding
    uint32_t total_length; // 64 to 1514 bytes
    payload_type_t payload_type;
} arp_config_t;

// Set default configuration for ARP Request/Reply
void arp_config_set_defaults(arp_config_t *cfg, uint16_t opcode);

// Build complete L2 Ethernet + ARP packet into buffer. Returns total size or 0 on failure.
size_t build_arp_packet(const arp_config_t *cfg, uint8_t *buffer, size_t max_buf_len);

// Parse raw frame for ARP header inside Ethernet frame
bool parse_arp_header(const uint8_t *buffer, size_t buf_len, arp_hdr_t *hdr_out, const uint8_t **payload_out, size_t *payload_len_out);

// Display parsed ARP header summary
void print_arp_header(const arp_hdr_t *hdr);

#endif // PKTX_ARP_H
