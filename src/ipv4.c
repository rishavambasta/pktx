#include "ipv4.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

void ipv4_config_set_defaults(ipv4_config_t *cfg) {
    if (!cfg) return;
    const uint8_t default_src_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    const uint8_t default_dst_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    memcpy(cfg->src_mac, default_src_mac, 6);
    memcpy(cfg->dst_mac, default_dst_mac, 6);

    cfg->tos = 0x00;
    cfg->id = 0x1234;
    cfg->dont_fragment = true;
    cfg->more_fragments = false;
    cfg->frag_offset = 0;
    cfg->ttl = 64;
    cfg->protocol = IP_PROTO_UDP;

    parse_ipv4_address("192.168.1.100", &cfg->src_ip);
    parse_ipv4_address("192.168.1.1", &cfg->dst_ip);

    cfg->auto_checksum = true;
    cfg->custom_checksum = 0;

    cfg->total_length = 64; // Default min size
    cfg->payload_type = PAYLOAD_ALL_ZEROS;
    cfg->payload_file_path[0] = '\0';
}

size_t build_ipv4_packet(const ipv4_config_t *cfg, uint8_t *buffer, size_t max_buf_len) {
    if (!cfg || !buffer) return 0;

    uint32_t total_pkt_len = cfg->total_length;
    if (total_pkt_len < PKTX_MIN_PACKET_SIZE) total_pkt_len = PKTX_MIN_PACKET_SIZE;
    if (total_pkt_len > PKTX_MAX_PACKET_SIZE) total_pkt_len = PKTX_MAX_PACKET_SIZE;
    if (max_buf_len < total_pkt_len) return 0;

    // 1. Build Ethernet Header
    eth_config_t eth_cfg;
    memcpy(eth_cfg.src_mac, cfg->src_mac, 6);
    memcpy(eth_cfg.dst_mac, cfg->dst_mac, 6);
    eth_cfg.ethertype = ETHER_TYPE_IPV4;
    eth_cfg.total_length = total_pkt_len;
    eth_cfg.payload_type = cfg->payload_type;
    strncpy(eth_cfg.payload_file_path, cfg->payload_file_path, sizeof(eth_cfg.payload_file_path) - 1);
    eth_cfg.payload_file_path[sizeof(eth_cfg.payload_file_path) - 1] = '\0';

    // First build L2 frame shell
    if (build_ethernet_packet(&eth_cfg, buffer, max_buf_len) == 0) return 0;

    // 2. Overwrite Ethernet payload with IPv4 header
    ipv4_hdr_t *ip_hdr = (ipv4_hdr_t *)(buffer + ETHER_HDR_LEN);
    ip_hdr->ver_ihl = (4 << 4) | 5; // Version 4, IHL 5 (20 bytes)
    ip_hdr->tos = cfg->tos;

    uint16_t ip_total_len = (uint16_t)(total_pkt_len - ETHER_HDR_LEN);
    ip_hdr->total_len = htons(ip_total_len);
    ip_hdr->id = htons(cfg->id);

    uint16_t flags_fo = (cfg->frag_offset & 0x1FFF);
    if (cfg->dont_fragment) flags_fo |= (1 << 14);
    if (cfg->more_fragments) flags_fo |= (1 << 13);
    ip_hdr->flags_offset = htons(flags_fo);

    ip_hdr->ttl = cfg->ttl;
    ip_hdr->protocol = cfg->protocol;
    ip_hdr->checksum = 0;
    ip_hdr->src_ip = cfg->src_ip;
    ip_hdr->dst_ip = cfg->dst_ip;

    if (cfg->auto_checksum) {
        ip_hdr->checksum = compute_checksum(ip_hdr, IPV4_HDR_LEN);
    } else {
        ip_hdr->checksum = htons(cfg->custom_checksum);
    }

    // 3. Fill IPv4 payload
    size_t ip_payload_len = ip_total_len - IPV4_HDR_LEN;
    uint8_t *ip_payload_ptr = buffer + ETHER_HDR_LEN + IPV4_HDR_LEN;
    generate_payload_ext(ip_payload_ptr, ip_payload_len, cfg->payload_type, cfg->payload_file_path);

    return total_pkt_len;
}

bool parse_ipv4_header(const uint8_t *buffer, size_t buf_len, ipv4_hdr_t *hdr_out, const uint8_t **payload_out, size_t *payload_len_out) {
    if (!buffer || buf_len < (ETHER_HDR_LEN + IPV4_HDR_LEN)) return false;

    eth_hdr_t eth;
    const uint8_t *eth_payload = NULL;
    size_t eth_payload_len = 0;
    if (!parse_ethernet_header(buffer, buf_len, &eth, &eth_payload, &eth_payload_len)) {
        return false;
    }

    if (eth.ethertype != ETHER_TYPE_IPV4) return false;

    const ipv4_hdr_t *raw_ip = (const ipv4_hdr_t *)eth_payload;
    uint8_t ihl = (raw_ip->ver_ihl & 0x0F) * 4;
    if (ihl < 20 || eth_payload_len < ihl) return false;

    if (hdr_out) {
        hdr_out->ver_ihl = raw_ip->ver_ihl;
        hdr_out->tos = raw_ip->tos;
        hdr_out->total_len = ntohs(raw_ip->total_len);
        hdr_out->id = ntohs(raw_ip->id);
        hdr_out->flags_offset = ntohs(raw_ip->flags_offset);
        hdr_out->ttl = raw_ip->ttl;
        hdr_out->protocol = raw_ip->protocol;
        hdr_out->checksum = ntohs(raw_ip->checksum);
        hdr_out->src_ip = raw_ip->src_ip;
        hdr_out->dst_ip = raw_ip->dst_ip;
    }

    if (payload_out) {
        *payload_out = eth_payload + ihl;
    }
    if (payload_len_out) {
        uint16_t ip_tot_len = ntohs(raw_ip->total_len);
        if (ip_tot_len >= ihl && ip_tot_len <= eth_payload_len) {
            *payload_len_out = ip_tot_len - ihl;
        } else {
            *payload_len_out = eth_payload_len - ihl;
        }
    }

    return true;
}

void print_ipv4_header(const ipv4_hdr_t *hdr) {
    if (!hdr) return;
    char src_ip_str[16], dst_ip_str[16];
    format_ipv4_address(hdr->src_ip, src_ip_str, sizeof(src_ip_str));
    format_ipv4_address(hdr->dst_ip, dst_ip_str, sizeof(dst_ip_str));

    uint8_t version = (hdr->ver_ihl >> 4) & 0x0F;
    uint8_t ihl = (hdr->ver_ihl & 0x0F) * 4;

    printf("=== IPv4 Header ===\n");
    printf("  Version         : %u\n", version);
    printf("  Header Length   : %u bytes (%u dwords)\n", ihl, ihl / 4);
    printf("  Type of Service : 0x%02X\n", hdr->tos);
    printf("  Total Length    : %u bytes\n", hdr->total_len);
    printf("  Identification  : 0x%04X (%u)\n", hdr->id, hdr->id);
    printf("  Flags           : 0x%04X (DF=%d, MF=%d)\n",
           hdr->flags_offset,
           (hdr->flags_offset & 0x4000) ? 1 : 0,
           (hdr->flags_offset & 0x2000) ? 1 : 0);
    printf("  Fragment Offset : %u\n", hdr->flags_offset & 0x1FFF);
    printf("  Time to Live    : %u\n", hdr->ttl);
    printf("  Protocol        : %u ", hdr->protocol);
    if (hdr->protocol == IP_PROTO_ICMP) printf("(ICMP)\n");
    else if (hdr->protocol == IP_PROTO_UDP) printf("(UDP)\n");
    else if (hdr->protocol == IP_PROTO_TCP) printf("(TCP)\n");
    else printf("(Other)\n");
    printf("  Header Checksum : 0x%04X\n", hdr->checksum);
    printf("  Source IP       : %s\n", src_ip_str);
    printf("  Destination IP  : %s\n", dst_ip_str);
}
