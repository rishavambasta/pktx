#include "utils.h"
#include "ethernet.h"
#include "ipv4.h"
#include "arp.h"
#include "payload.h"
#include "strm.h"
#include "pcapng.h"
#include "transmitter.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static int tests_passed = 0;
static int tests_total = 0;

#define TEST_ASSERT(cond, name) do { \
    tests_total++; \
    if (cond) { \
        tests_passed++; \
        printf("  [PASS] %s\n", name); \
    } else { \
        printf("  [FAIL] %s\n", name); \
    } \
} while (0)

static void test_utils(void) {
    printf("=== Running Utils Tests ===\n");
    uint8_t mac[6];
    TEST_ASSERT(parse_mac_address("00:11:22:33:44:55", mac), "parse_mac_address colon format");
    TEST_ASSERT(mac[0] == 0x00 && mac[5] == 0x55, "parse_mac_address values");

    char mac_str[18];
    format_mac_address(mac, mac_str, sizeof(mac_str));
    TEST_ASSERT(strcmp(mac_str, "00:11:22:33:44:55") == 0, "format_mac_address format");

    uint32_t ip;
    TEST_ASSERT(parse_ipv4_address("192.168.1.100", &ip), "parse_ipv4_address valid");
    char ip_str[16];
    format_ipv4_address(ip, ip_str, sizeof(ip_str));
    TEST_ASSERT(strcmp(ip_str, "192.168.1.100") == 0, "format_ipv4_address format");

    uint16_t hex_val;
    TEST_ASSERT(parse_hex16("0x0800", &hex_val) && hex_val == 0x0800, "parse_hex16 with 0x prefix");
    TEST_ASSERT(parse_hex16("0806", &hex_val) && hex_val == 0x0806, "parse_hex16 without prefix");
}

static void test_payload(void) {
    printf("\n=== Running Payload Tests ===\n");
    uint8_t buf[100];

    generate_payload(buf, sizeof(buf), PAYLOAD_ALL_ZEROS);
    bool zeros_ok = true;
    for (size_t i = 0; i < sizeof(buf); i++) if (buf[i] != 0x00) zeros_ok = false;
    TEST_ASSERT(zeros_ok, "generate_payload ALL_ZEROS");

    generate_payload(buf, sizeof(buf), PAYLOAD_ALL_ONES);
    bool ones_ok = true;
    for (size_t i = 0; i < sizeof(buf); i++) if (buf[i] != 0xFF) ones_ok = false;
    TEST_ASSERT(ones_ok, "generate_payload ALL_ONES");

    generate_payload(buf, sizeof(buf), PAYLOAD_PSEUDO_RANDOM);
    bool rand_ok = false;
    for (size_t i = 1; i < sizeof(buf); i++) {
        if (buf[i] != buf[0]) rand_ok = true;
    }
    TEST_ASSERT(rand_ok, "generate_payload PSEUDO_RANDOM non-uniformity");

    // Test binary file payload
    FILE *tf = fopen("test_payload.bin", "wb");
    if (tf) {
        uint8_t sample_bytes[4] = {0xDE, 0xAD, 0xBE, 0xEF};
        fwrite(sample_bytes, 1, 4, tf);
        fclose(tf);

        generate_payload_ext(buf, 10, PAYLOAD_FILE, "test_payload.bin");
        TEST_ASSERT(buf[0] == 0xDE && buf[1] == 0xAD && buf[2] == 0xBE && buf[3] == 0xEF && buf[4] == 0xDE, "generate_payload_ext binary file pattern repeat");
        remove("test_payload.bin");
    }
}

static void test_ethernet(void) {
    printf("\n=== Running Ethernet Tests ===\n");
    eth_config_t cfg;
    eth_config_set_defaults(&cfg);
    cfg.total_length = 64;
    cfg.payload_type = PAYLOAD_ALL_ONES;

    uint8_t pkt_buf[PKTX_MAX_PACKET_SIZE];
    size_t len = build_ethernet_packet(&cfg, pkt_buf, sizeof(pkt_buf));
    TEST_ASSERT(len == 64, "build_ethernet_packet length 64");

    eth_hdr_t parsed_eth;
    const uint8_t *payload = NULL;
    size_t payload_len = 0;
    TEST_ASSERT(parse_ethernet_header(pkt_buf, len, &parsed_eth, &payload, &payload_len), "parse_ethernet_header success");
    TEST_ASSERT(parsed_eth.ethertype == ETHER_TYPE_IPV4, "parse_ethernet_header ethertype IPv4");
    TEST_ASSERT(payload_len == (64 - ETHER_HDR_LEN), "parse_ethernet_header payload length");
    TEST_ASSERT(payload[0] == 0xFF, "Ethernet payload filled with ones");
}

static void test_ipv4(void) {
    printf("\n=== Running IPv4 Tests ===\n");
    ipv4_config_t cfg;
    ipv4_config_set_defaults(&cfg);
    cfg.total_length = 100;
    cfg.payload_type = PAYLOAD_ALL_ZEROS;

    uint8_t pkt_buf[PKTX_MAX_PACKET_SIZE];
    size_t len = build_ipv4_packet(&cfg, pkt_buf, sizeof(pkt_buf));
    TEST_ASSERT(len == 100, "build_ipv4_packet total size 100");

    ipv4_hdr_t ip_hdr;
    const uint8_t *ip_payload = NULL;
    size_t ip_payload_len = 0;
    TEST_ASSERT(parse_ipv4_header(pkt_buf, len, &ip_hdr, &ip_payload, &ip_payload_len), "parse_ipv4_header success");
    TEST_ASSERT(ip_hdr.protocol == IP_PROTO_UDP, "parse_ipv4_header protocol UDP");
    TEST_ASSERT(ip_hdr.total_len == (100 - ETHER_HDR_LEN), "parse_ipv4_header total length calculation");

    // Verify Checksum
    const uint8_t *raw_ip = pkt_buf + ETHER_HDR_LEN;
    uint16_t chk = compute_checksum(raw_ip, IPV4_HDR_LEN);
    TEST_ASSERT(chk == 0, "IPv4 Internet Checksum validation (sum should be 0)");
}

static void test_arp(void) {
    printf("\n=== Running ARP Tests ===\n");
    arp_config_t cfg;
    arp_config_set_defaults(&cfg, ARP_OP_REQUEST);

    uint8_t pkt_buf[PKTX_MAX_PACKET_SIZE];
    size_t len = build_arp_packet(&cfg, pkt_buf, sizeof(pkt_buf));
    TEST_ASSERT(len == 64, "build_arp_packet total size 64");

    eth_hdr_t eth_hdr;
    TEST_ASSERT(parse_ethernet_header(pkt_buf, len, &eth_hdr, NULL, NULL), "parse_ethernet_header on ARP frame");
    TEST_ASSERT(eth_hdr.ethertype == ETHER_TYPE_ARP, "EtherType is ARP (0x0806)");

    arp_hdr_t arp_hdr;
    const uint8_t *arp_pad = NULL;
    size_t arp_pad_len = 0;
    TEST_ASSERT(parse_arp_header(pkt_buf, len, &arp_hdr, &arp_pad, &arp_pad_len), "parse_arp_header success");
    TEST_ASSERT(arp_hdr.opcode == ARP_OP_REQUEST, "parse_arp_header opcode Request (1)");
    TEST_ASSERT(arp_hdr.htype == 1 && arp_hdr.ptype == 0x0800, "ARP hardware/protocol types");

    // Test ARP Reply building
    arp_config_set_defaults(&cfg, ARP_OP_REPLY);
    len = build_arp_packet(&cfg, pkt_buf, sizeof(pkt_buf));
    TEST_ASSERT(parse_arp_header(pkt_buf, len, &arp_hdr, NULL, NULL), "parse_arp_header on ARP Reply");
    TEST_ASSERT(arp_hdr.opcode == ARP_OP_REPLY, "parse_arp_header opcode Reply (2)");
}

static void test_strm(void) {
    printf("\n=== Running Stream (.strm) Tests ===\n");
    strm_stream_t stream_out, stream_in;
    strm_init(&stream_out, 3);
    strm_init(&stream_in, 0);

    ipv4_config_t cfg;
    ipv4_config_set_defaults(&cfg);
    cfg.total_length = 128;
    cfg.payload_type = PAYLOAD_ALL_ONES;

    uint8_t pkt_buf[PKTX_MAX_PACKET_SIZE];
    size_t len = build_ipv4_packet(&cfg, pkt_buf, sizeof(pkt_buf));

    TEST_ASSERT(strm_add_packet(&stream_out, pkt_buf, len, 10, 5), "strm_add_packet entry 1");
    TEST_ASSERT(strm_save_file("test_out.strm", &stream_out), "strm_save_file");

    TEST_ASSERT(strm_load_file("test_out.strm", &stream_in), "strm_load_file");
    TEST_ASSERT(stream_in.count == 1, "strm_load_file count matches");
    TEST_ASSERT(stream_in.entries[0].pkt_len == 128, "strm_load_file pkt_len matches");
    TEST_ASSERT(stream_in.entries[0].delay_ms == 10, "strm_load_file delay_ms matches");
    TEST_ASSERT(stream_in.entries[0].repetitions == 5, "strm_load_file repetitions match");
    TEST_ASSERT(memcmp(stream_in.entries[0].raw_data, pkt_buf, len) == 0, "strm_load_file raw packet bytes match");

    strm_free(&stream_out);
    strm_free(&stream_in);
    remove("test_out.strm");
}

static void test_transmitter_dry_run(void) {
    printf("\n=== Running Transmitter Dry-Run Tests ===\n");
    eth_config_t cfg;
    eth_config_set_defaults(&cfg);
    uint8_t pkt_buf[PKTX_MAX_PACKET_SIZE];
    size_t len = build_ethernet_packet(&cfg, pkt_buf, sizeof(pkt_buf));

    strm_stream_t stream;
    strm_init(&stream, 2);
    strm_add_packet(&stream, pkt_buf, len, 0, 2);

    tx_options_t tx_opts;
    tx_options_set_defaults(&tx_opts);
    tx_opts.dry_run = true;
    tx_opts.count = 1;

    TEST_ASSERT(transmit_stream(&stream, &tx_opts), "transmit_stream dry-run execution");
    strm_free(&stream);
}

int main(void) {
    printf("Starting pktx unit test suite...\n\n");
    test_utils();
    test_payload();
    test_ethernet();
    test_ipv4();
    test_arp();
    test_strm();
    test_transmitter_dry_run();

    printf("\n=========================================\n");
    printf("Test Results: %d / %d tests passed.\n", tests_passed, tests_total);
    printf("=========================================\n");

    return (tests_passed == tests_total) ? 0 : 1;
}
