#include "arp.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

void arp_config_set_defaults(arp_config_t *cfg, uint16_t opcode) {
    if (!cfg) return;
    const uint8_t default_src_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    const uint8_t default_dst_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    const uint8_t zero_mac[6]        = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    cfg->htype = ARP_HTYPE_ETHERNET;
    cfg->ptype = ARP_PTYPE_IPV4;
    cfg->hlen = 6;
    cfg->plen = 4;
    cfg->opcode = (opcode == ARP_OP_REPLY) ? ARP_OP_REPLY : ARP_OP_REQUEST;

    memcpy(cfg->src_mac, default_src_mac, 6);
    memcpy(cfg->sender_mac, default_src_mac, 6);

    if (cfg->opcode == ARP_OP_REQUEST) {
        memcpy(cfg->dst_mac, default_dst_mac, 6);
        memcpy(cfg->target_mac, zero_mac, 6);
        parse_ipv4_address("192.168.1.100", &cfg->sender_ip);
        parse_ipv4_address("192.168.1.1", &cfg->target_ip);
    } else {
        const uint8_t reply_target_mac[6] = {0x66, 0x55, 0x44, 0x33, 0x22, 0x11};
        memcpy(cfg->dst_mac, reply_target_mac, 6);
        memcpy(cfg->target_mac, reply_target_mac, 6);
        parse_ipv4_address("192.168.1.1", &cfg->sender_ip);
        parse_ipv4_address("192.168.1.100", &cfg->target_ip);
    }

    cfg->total_length = 64; // Min Ethernet frame size
    cfg->payload_type = PAYLOAD_ALL_ZEROS;
}

size_t build_arp_packet(const arp_config_t *cfg, uint8_t *buffer, size_t max_buf_len) {
    if (!cfg || !buffer) return 0;

    uint32_t total_pkt_len = cfg->total_length;
    if (total_pkt_len < PKTX_MIN_PACKET_SIZE) total_pkt_len = PKTX_MIN_PACKET_SIZE;
    if (total_pkt_len > PKTX_MAX_PACKET_SIZE) total_pkt_len = PKTX_MAX_PACKET_SIZE;
    if (max_buf_len < total_pkt_len) return 0;

    // 1. Build Ethernet Header
    eth_config_t eth_cfg;
    memcpy(eth_cfg.src_mac, cfg->src_mac, 6);
    memcpy(eth_cfg.dst_mac, cfg->dst_mac, 6);
    eth_cfg.ethertype = ETHER_TYPE_ARP;
    eth_cfg.total_length = total_pkt_len;
    eth_cfg.payload_type = cfg->payload_type;

    if (build_ethernet_packet(&eth_cfg, buffer, max_buf_len) == 0) return 0;

    // 2. Overwrite payload with ARP Header
    arp_hdr_t *arp = (arp_hdr_t *)(buffer + ETHER_HDR_LEN);
    arp->htype = htons(cfg->htype);
    arp->ptype = htons(cfg->ptype);
    arp->hlen = cfg->hlen;
    arp->plen = cfg->plen;
    arp->opcode = htons(cfg->opcode);

    memcpy(arp->sender_mac, cfg->sender_mac, 6);
    arp->sender_ip = cfg->sender_ip;

    memcpy(arp->target_mac, cfg->target_mac, 6);
    arp->target_ip = cfg->target_ip;

    // 3. Fill remaining padding payload after ARP header
    size_t arp_payload_len = total_pkt_len - ETHER_HDR_LEN - ARP_HDR_LEN;
    if (arp_payload_len > 0) {
        uint8_t *pad_ptr = buffer + ETHER_HDR_LEN + ARP_HDR_LEN;
        generate_payload(pad_ptr, arp_payload_len, cfg->payload_type);
    }

    return total_pkt_len;
}

bool parse_arp_header(const uint8_t *buffer, size_t buf_len, arp_hdr_t *hdr_out, const uint8_t **payload_out, size_t *payload_len_out) {
    if (!buffer || buf_len < (ETHER_HDR_LEN + ARP_HDR_LEN)) return false;

    eth_hdr_t eth;
    const uint8_t *eth_payload = NULL;
    size_t eth_payload_len = 0;
    if (!parse_ethernet_header(buffer, buf_len, &eth, &eth_payload, &eth_payload_len)) {
        return false;
    }

    if (eth.ethertype != ETHER_TYPE_ARP) return false;
    if (eth_payload_len < ARP_HDR_LEN) return false;

    const arp_hdr_t *raw_arp = (const arp_hdr_t *)eth_payload;

    if (hdr_out) {
        hdr_out->htype = ntohs(raw_arp->htype);
        hdr_out->ptype = ntohs(raw_arp->ptype);
        hdr_out->hlen = raw_arp->hlen;
        hdr_out->plen = raw_arp->plen;
        hdr_out->opcode = ntohs(raw_arp->opcode);
        memcpy(hdr_out->sender_mac, raw_arp->sender_mac, 6);
        hdr_out->sender_ip = raw_arp->sender_ip;
        memcpy(hdr_out->target_mac, raw_arp->target_mac, 6);
        hdr_out->target_ip = raw_arp->target_ip;
    }

    if (payload_out) {
        *payload_out = eth_payload + ARP_HDR_LEN;
    }
    if (payload_len_out) {
        *payload_len_out = eth_payload_len - ARP_HDR_LEN;
    }

    return true;
}

void print_arp_header(const arp_hdr_t *hdr) {
    if (!hdr) return;
    char sender_mac_str[18], target_mac_str[18];
    char sender_ip_str[16], target_ip_str[16];

    format_mac_address(hdr->sender_mac, sender_mac_str, sizeof(sender_mac_str));
    format_mac_address(hdr->target_mac, target_mac_str, sizeof(target_mac_str));
    format_ipv4_address(hdr->sender_ip, sender_ip_str, sizeof(sender_ip_str));
    format_ipv4_address(hdr->target_ip, target_ip_str, sizeof(target_ip_str));

    printf("=== ARP Header ===\n");
    printf("  Hardware Type   : %u (Ethernet)\n", hdr->htype);
    printf("  Protocol Type   : 0x%04X (IPv4)\n", hdr->ptype);
    printf("  Hardware Size   : %u bytes\n", hdr->hlen);
    printf("  Protocol Size   : %u bytes\n", hdr->plen);
    printf("  Opcode          : %u ", hdr->opcode);
    if (hdr->opcode == ARP_OP_REQUEST) printf("(ARP Request / Who Has?)\n");
    else if (hdr->opcode == ARP_OP_REPLY) printf("(ARP Reply / Is At)\n");
    else printf("(Unknown)\n");
    printf("  Sender MAC      : %s\n", sender_mac_str);
    printf("  Sender IP       : %s\n", sender_ip_str);
    printf("  Target MAC      : %s\n", target_mac_str);
    printf("  Target IP       : %s\n", target_ip_str);
}
