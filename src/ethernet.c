#include "ethernet.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

void eth_config_set_defaults(eth_config_t *cfg) {
    if (!cfg) return;
    // Default MACs: Src 00:11:22:33:44:55, Dst Broadcast FF:FF:FF:FF:FF:FF
    const uint8_t default_src[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    const uint8_t default_dst[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    memcpy(cfg->src_mac, default_src, 6);
    memcpy(cfg->dst_mac, default_dst, 6);
    cfg->ethertype = ETHER_TYPE_IPV4;
    cfg->total_length = 64; // Default min size
    cfg->payload_type = PAYLOAD_ALL_ZEROS;
}

size_t build_ethernet_packet(const eth_config_t *cfg, uint8_t *buffer, size_t max_buf_len) {
    if (!cfg || !buffer) return 0;

    uint32_t pkt_size = cfg->total_length;
    if (pkt_size < PKTX_MIN_PACKET_SIZE) pkt_size = PKTX_MIN_PACKET_SIZE;
    if (pkt_size > PKTX_MAX_PACKET_SIZE) pkt_size = PKTX_MAX_PACKET_SIZE;
    if (max_buf_len < pkt_size) return 0;

    eth_hdr_t *hdr = (eth_hdr_t *)buffer;
    memcpy(hdr->dst_mac, cfg->dst_mac, 6);
    memcpy(hdr->src_mac, cfg->src_mac, 6);
    hdr->ethertype = htons(cfg->ethertype);

    size_t payload_size = pkt_size - ETHER_HDR_LEN;
    uint8_t *payload_ptr = buffer + ETHER_HDR_LEN;
    generate_payload(payload_ptr, payload_size, cfg->payload_type);

    return pkt_size;
}

bool parse_ethernet_header(const uint8_t *buffer, size_t buf_len, eth_hdr_t *hdr_out, const uint8_t **payload_out, size_t *payload_len_out) {
    if (!buffer || buf_len < ETHER_HDR_LEN) return false;

    const eth_hdr_t *hdr = (const eth_hdr_t *)buffer;
    if (hdr_out) {
        memcpy(hdr_out->dst_mac, hdr->dst_mac, 6);
        memcpy(hdr_out->src_mac, hdr->src_mac, 6);
        hdr_out->ethertype = ntohs(hdr->ethertype);
    }
    if (payload_out) {
        *payload_out = buffer + ETHER_HDR_LEN;
    }
    if (payload_len_out) {
        *payload_len_out = buf_len - ETHER_HDR_LEN;
    }
    return true;
}

void print_ethernet_header(const eth_hdr_t *hdr, size_t total_len) {
    if (!hdr) return;
    char src_str[18], dst_str[18];
    format_mac_address(hdr->src_mac, src_str, sizeof(src_str));
    format_mac_address(hdr->dst_mac, dst_str, sizeof(dst_str));

    printf("=== Ethernet II Header ===\n");
    printf("  Destination MAC : %s\n", dst_str);
    printf("  Source MAC      : %s\n", src_str);
    printf("  EtherType       : 0x%04X ", hdr->ethertype);
    if (hdr->ethertype == ETHER_TYPE_IPV4) printf("(IPv4)\n");
    else if (hdr->ethertype == ETHER_TYPE_ARP) printf("(ARP)\n");
    else if (hdr->ethertype == ETHER_TYPE_IPV6) printf("(IPv6)\n");
    else printf("(Unknown)\n");
    printf("  Total Packet Size: %zu bytes\n", total_len);
}
