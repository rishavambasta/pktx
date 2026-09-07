#include "cli.h"
#include "pktx.h"
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
#include <ctype.h>
#include <getopt.h>

#ifdef _WIN32
#ifndef strcasecmp
#define strcasecmp _stricmp
#endif
#ifndef strncasecmp
#define strncasecmp _strnicmp
#endif
#endif

// Read a non-empty string line with default fallback
static void prompt_string(const char *label, const char *default_val, char *buf, size_t buf_len) {
    printf("%s [%s]: ", label, default_val ? default_val : "");
    fflush(stdout);

    char temp[256];
    if (fgets(temp, sizeof(temp), stdin)) {
        temp[strcspn(temp, "\r\n")] = '\0';
        if (strlen(temp) == 0 && default_val) {
            strncpy(buf, default_val, buf_len - 1);
            buf[buf_len - 1] = '\0';
        } else {
            strncpy(buf, temp, buf_len - 1);
            buf[buf_len - 1] = '\0';
        }
    } else if (default_val) {
        strncpy(buf, default_val, buf_len - 1);
        buf[buf_len - 1] = '\0';
    }
}

static void prompt_mac(const char *label, const uint8_t default_mac[6], uint8_t out_mac[6]) {
    char def_str[18];
    format_mac_address(default_mac, def_str, sizeof(def_str));
    char input[64];

    while (1) {
        prompt_string(label, def_str, input, sizeof(input));
        if (parse_mac_address(input, out_mac)) {
            break;
        }
        printf("  [!] Invalid MAC address format. Expected AA:BB:CC:DD:EE:FF. Try again.\n");
    }
}

static void prompt_ipv4(const char *label, uint32_t default_ip, uint32_t *out_ip) {
    char def_str[16];
    format_ipv4_address(default_ip, def_str, sizeof(def_str));
    char input[64];

    while (1) {
        prompt_string(label, def_str, input, sizeof(input));
        if (parse_ipv4_address(input, out_ip)) {
            break;
        }
        printf("  [!] Invalid IPv4 address format. Expected A.B.C.D. Try again.\n");
    }
}

static uint32_t prompt_uint(const char *label, uint32_t default_val, uint32_t min_val, uint32_t max_val) {
    char def_str[32];
    snprintf(def_str, sizeof(def_str), "%u", default_val);
    char input[64];
    uint32_t val;

    while (1) {
        prompt_string(label, def_str, input, sizeof(input));
        if (parse_uint(input, min_val, max_val, &val)) {
            return val;
        }
        printf("  [!] Invalid integer or out of range [%u .. %u]. Try again.\n", min_val, max_val);
    }
}

static uint16_t prompt_hex16(const char *label, uint16_t default_val) {
    char def_str[32];
    snprintf(def_str, sizeof(def_str), "0x%04X", default_val);
    char input[64];
    uint16_t val;

    while (1) {
        prompt_string(label, def_str, input, sizeof(input));
        if (parse_hex16(input, &val)) {
            return val;
        }
        printf("  [!] Invalid hex format (e.g. 0x0800). Try again.\n");
    }
}

static payload_type_t prompt_payload_type(char *file_path_out, size_t file_path_len) {
    printf("\n--- Payload Options ---\n");
    printf("  1. All 0s (0x00...00)\n");
    printf("  2. All 1s (0xFF...FF)\n");
    printf("  3. Pseudo-random bytes\n");
    printf("  4. Binary file content\n");
    uint32_t choice = prompt_uint("Select payload pattern", 1, 1, 4);

    if (choice == 4 && file_path_out && file_path_len > 0) {
        prompt_string("Enter path to binary payload file", "payload.bin", file_path_out, file_path_len);
    } else if (file_path_out && file_path_len > 0) {
        file_path_out[0] = '\0';
    }

    return (payload_type_t)choice;
}

static void prompt_transmission(strm_stream_t *stream) {
    printf("\n--- Packet Transmission ---\n");
    if_list_t if_list;
    get_network_interfaces(&if_list);
    print_network_interfaces(&if_list);

    tx_options_t tx_opts;
    tx_options_set_defaults(&tx_opts);

    if (if_list.count > 0) {
        char prompt_lbl[64];
        snprintf(prompt_lbl, sizeof(prompt_lbl), "Select target network interface index [1-%zu]", if_list.count);
        uint32_t if_idx = prompt_uint(prompt_lbl, 1, 1, (uint32_t)if_list.count);
        strncpy(tx_opts.interface_name, if_list.interfaces[if_idx - 1].name, sizeof(tx_opts.interface_name) - 1);
    } else {
        char if_input[256];
        prompt_string("Enter target network interface name", tx_opts.interface_name, if_input, sizeof(if_input));
        strncpy(tx_opts.interface_name, if_input, sizeof(tx_opts.interface_name) - 1);
    }

    tx_opts.count = prompt_uint("Enter transmission repetitions (0 for continuous loop, default 1)", 1, 0, 1000000);
    tx_opts.delay_ms = prompt_uint("Enter Inter-Packet Gap (IPG) / delay in milliseconds (0 for minimal IPG)", 0, 0, 60000);

    printf("Enable dry-run simulation mode? (1=Yes, 0=No) [0]: ");
    fflush(stdout);
    char dry_str[16];
    if (fgets(dry_str, sizeof(dry_str), stdin)) {
        dry_str[strcspn(dry_str, "\r\n")] = '\0';
        if (strcmp(dry_str, "1") == 0 || strcasecmp(dry_str, "y") == 0 || strcasecmp(dry_str, "yes") == 0) {
            tx_opts.dry_run = true;
        }
    }

    transmit_stream(stream, &tx_opts);
}

static void build_l2_interactive(void) {
    printf("\n=========================================\n");
    printf("        L2 Ethernet Packet Generator     \n");
    printf("=========================================\n");

    eth_config_t cfg;
    eth_config_set_defaults(&cfg);

    prompt_mac("Destination MAC", cfg.dst_mac, cfg.dst_mac);
    prompt_mac("Source MAC", cfg.src_mac, cfg.src_mac);
    cfg.ethertype = prompt_hex16("EtherType (e.g. 0x0800 for IPv4, 0x0806 for ARP)", cfg.ethertype);

    cfg.total_length = prompt_uint("Total Packet Size (bytes)", 64, PKTX_MIN_PACKET_SIZE, PKTX_MAX_PACKET_SIZE);
    cfg.payload_type = prompt_payload_type(cfg.payload_file_path, sizeof(cfg.payload_file_path));

    uint8_t pkt_buf[PKTX_MAX_PACKET_SIZE];
    size_t pkt_len = build_ethernet_packet(&cfg, pkt_buf, sizeof(pkt_buf));

    if (pkt_len == 0) {
        printf("\n[!] Error building Ethernet packet.\n");
        return;
    }

    printf("\n--- Generated L2 Packet Frame ---\n");
    eth_hdr_t eth_hdr;
    parse_ethernet_header(pkt_buf, pkt_len, &eth_hdr, NULL, NULL);
    print_ethernet_header(&eth_hdr, pkt_len);
    print_hex_dump("Raw Packet Bytes", pkt_buf, pkt_len);

    strm_stream_t stream;
    strm_init(&stream, 2);
    strm_add_packet(&stream, pkt_buf, pkt_len, 0, 1);

    char save_choice[16];
    prompt_string("\nSave packet stream to .strm file? (y/n)", "y", save_choice, sizeof(save_choice));
    if (strcasecmp(save_choice, "y") == 0 || strcasecmp(save_choice, "yes") == 0) {
        char strm_path[256];
        prompt_string("Enter .strm output filename", "l2_stream.strm", strm_path, sizeof(strm_path));
        if (strm_save_file(strm_path, &stream)) {
            printf("[+] Successfully saved packet stream to '%s'\n", strm_path);
        } else {
            printf("[!] Failed to save .strm file.\n");
        }
    }

    char tx_choice[16];
    prompt_string("Transmit packet now? (y/n)", "y", tx_choice, sizeof(tx_choice));
    if (strcasecmp(tx_choice, "y") == 0 || strcasecmp(tx_choice, "yes") == 0) {
        prompt_transmission(&stream);
    }

    strm_free(&stream);
}

static void build_l3_interactive(void) {
    printf("\n=========================================\n");
    printf("        L3 IPv4 Packet Generator         \n");
    printf("=========================================\n");

    ipv4_config_t cfg;
    ipv4_config_set_defaults(&cfg);

    printf("\n--- L2 Header Fields ---\n");
    prompt_mac("Destination MAC", cfg.dst_mac, cfg.dst_mac);
    prompt_mac("Source MAC", cfg.src_mac, cfg.src_mac);

    printf("\n--- L3 IPv4 Header Fields ---\n");
    prompt_ipv4("Source IP Address", cfg.src_ip, &cfg.src_ip);
    prompt_ipv4("Destination IP Address", cfg.dst_ip, &cfg.dst_ip);

    cfg.ttl = (uint8_t)prompt_uint("Time to Live (TTL)", cfg.ttl, 1, 255);
    cfg.protocol = (uint8_t)prompt_uint("Protocol (1=ICMP, 6=TCP, 17=UDP, 255=Raw)", cfg.protocol, 0, 255);
    cfg.tos = (uint8_t)prompt_uint("Type of Service / TOS / DSCP", cfg.tos, 0, 255);
    cfg.id = prompt_hex16("Identification (ID)", cfg.id);

    uint32_t df = prompt_uint("Don't Fragment (DF) flag (1=Set, 0=Clear)", 1, 0, 1);
    cfg.dont_fragment = (df == 1);

    uint32_t mf = prompt_uint("More Fragments (MF) flag (1=Set, 0=Clear)", 0, 0, 1);
    cfg.more_fragments = (mf == 1);

    cfg.frag_offset = (uint16_t)prompt_uint("Fragment Offset", 0, 0, 8191);

    uint32_t chk_choice = prompt_uint("Header Checksum calculation (1=Auto compute RFC1071, 0=Custom manual hex)", 1, 0, 1);
    if (chk_choice == 1) {
        cfg.auto_checksum = true;
    } else {
        cfg.auto_checksum = false;
        cfg.custom_checksum = prompt_hex16("Custom Checksum Value", 0x1234);
    }

    cfg.total_length = prompt_uint("\nTotal Frame Size (bytes)", 64, PKTX_MIN_PACKET_SIZE, PKTX_MAX_PACKET_SIZE);
    cfg.payload_type = prompt_payload_type(cfg.payload_file_path, sizeof(cfg.payload_file_path));

    uint8_t pkt_buf[PKTX_MAX_PACKET_SIZE];
    size_t pkt_len = build_ipv4_packet(&cfg, pkt_buf, sizeof(pkt_buf));

    if (pkt_len == 0) {
        printf("\n[!] Error building IPv4 packet.\n");
        return;
    }

    printf("\n--- Generated L3 Packet Frame ---\n");
    eth_hdr_t eth_hdr;
    parse_ethernet_header(pkt_buf, pkt_len, &eth_hdr, NULL, NULL);
    print_ethernet_header(&eth_hdr, pkt_len);

    ipv4_hdr_t ip_hdr;
    parse_ipv4_header(pkt_buf, pkt_len, &ip_hdr, NULL, NULL);
    print_ipv4_header(&ip_hdr);
    print_hex_dump("Raw Packet Bytes", pkt_buf, pkt_len);

    strm_stream_t stream;
    strm_init(&stream, 3);
    strm_add_packet(&stream, pkt_buf, pkt_len, 0, 1);

    char save_choice[16];
    prompt_string("\nSave packet stream to .strm file? (y/n)", "y", save_choice, sizeof(save_choice));
    if (strcasecmp(save_choice, "y") == 0 || strcasecmp(save_choice, "yes") == 0) {
        char strm_path[256];
        prompt_string("Enter .strm output filename", "l3_stream.strm", strm_path, sizeof(strm_path));
        if (strm_save_file(strm_path, &stream)) {
            printf("[+] Successfully saved packet stream to '%s'\n", strm_path);
        } else {
            printf("[!] Failed to save .strm file.\n");
        }
    }

    char tx_choice[16];
    prompt_string("Transmit packet now? (y/n)", "y", tx_choice, sizeof(tx_choice));
    if (strcasecmp(tx_choice, "y") == 0 || strcasecmp(tx_choice, "yes") == 0) {
        prompt_transmission(&stream);
    }

    strm_free(&stream);
}

static void build_arp_interactive(void) {
    printf("\n=========================================\n");
    printf("        ARP Packet Generator             \n");
    printf("=========================================\n");

    uint32_t op_choice = prompt_uint("Select ARP Operation (1 = Request [Who Has?], 2 = Reply [Is At])", 1, 1, 2);

    arp_config_t cfg;
    arp_config_set_defaults(&cfg, (uint16_t)op_choice);

    printf("\n--- L2 Ethernet Header Fields ---\n");
    prompt_mac("Destination MAC", cfg.dst_mac, cfg.dst_mac);
    prompt_mac("Source MAC", cfg.src_mac, cfg.src_mac);

    printf("\n--- ARP Header Fields ---\n");
    prompt_mac("Sender MAC Address", cfg.sender_mac, cfg.sender_mac);
    prompt_ipv4("Sender IP Address", cfg.sender_ip, &cfg.sender_ip);
    prompt_mac("Target MAC Address", cfg.target_mac, cfg.target_mac);
    prompt_ipv4("Target IP Address", cfg.target_ip, &cfg.target_ip);

    cfg.total_length = prompt_uint("\nTotal Frame Size (bytes)", 64, PKTX_MIN_PACKET_SIZE, PKTX_MAX_PACKET_SIZE);
    cfg.payload_type = prompt_payload_type(cfg.payload_file_path, sizeof(cfg.payload_file_path));

    uint8_t pkt_buf[PKTX_MAX_PACKET_SIZE];
    size_t pkt_len = build_arp_packet(&cfg, pkt_buf, sizeof(pkt_buf));

    if (pkt_len == 0) {
        printf("\n[!] Error building ARP packet.\n");
        return;
    }

    printf("\n--- Generated ARP Packet Frame ---\n");
    eth_hdr_t eth_hdr;
    parse_ethernet_header(pkt_buf, pkt_len, &eth_hdr, NULL, NULL);
    print_ethernet_header(&eth_hdr, pkt_len);

    arp_hdr_t arp_hdr;
    parse_arp_header(pkt_buf, pkt_len, &arp_hdr, NULL, NULL);
    print_arp_header(&arp_hdr);
    print_hex_dump("Raw Packet Bytes", pkt_buf, pkt_len);

    strm_stream_t stream;
    strm_init(&stream, 2);
    strm_add_packet(&stream, pkt_buf, pkt_len, 0, 1);

    char save_choice[16];
    prompt_string("\nSave packet stream to .strm file? (y/n)", "y", save_choice, sizeof(save_choice));
    if (strcasecmp(save_choice, "y") == 0 || strcasecmp(save_choice, "yes") == 0) {
        char strm_path[256];
        prompt_string("Enter .strm output filename", "arp_stream.strm", strm_path, sizeof(strm_path));
        if (strm_save_file(strm_path, &stream)) {
            printf("[+] Successfully saved packet stream to '%s'\n", strm_path);
        } else {
            printf("[!] Failed to save .strm file.\n");
        }
    }

    char tx_choice[16];
    prompt_string("Transmit packet now? (y/n)", "y", tx_choice, sizeof(tx_choice));
    if (strcasecmp(tx_choice, "y") == 0 || strcasecmp(tx_choice, "yes") == 0) {
        prompt_transmission(&stream);
    }

    strm_free(&stream);
}

static void parse_pcap_interactive(void) {
    printf("\n=========================================\n");
    printf("      Wireshark Pcap / Pcapng Parser     \n");
    printf("=========================================\n");

    char pcap_path[256];
    prompt_string("Enter path to .pcap or .pcapng file", "sample.pcapng", pcap_path, sizeof(pcap_path));

    strm_stream_t stream;
    strm_init(&stream, 2);

    if (!parse_pcap_or_pcapng_file(pcap_path, &stream)) {
        printf("[!] Failed to open or parse PCAP file '%s'\n", pcap_path);
        strm_free(&stream);
        return;
    }

    printf("\n[+] Successfully parsed %zu packet(s) from '%s'\n", stream.count, pcap_path);
    strm_print_info(&stream);

    char save_choice[16];
    prompt_string("\nSave converted packets to .strm stream format? (y/n)", "y", save_choice, sizeof(save_choice));
    if (strcasecmp(save_choice, "y") == 0 || strcasecmp(save_choice, "yes") == 0) {
        char strm_path[256];
        prompt_string("Enter .strm output filename", "converted_pcap.strm", strm_path, sizeof(strm_path));
        if (strm_save_file(strm_path, &stream)) {
            printf("[+] Saved %zu packet(s) to '%s'\n", stream.count, strm_path);
        } else {
            printf("[!] Error saving .strm file.\n");
        }
    }

    char tx_choice[16];
    prompt_string("Transmit captured packets now? (y/n)", "n", tx_choice, sizeof(tx_choice));
    if (strcasecmp(tx_choice, "y") == 0 || strcasecmp(tx_choice, "yes") == 0) {
        prompt_transmission(&stream);
    }

    strm_free(&stream);
}

static void load_strm_interactive(void) {
    printf("\n=========================================\n");
    printf("         Load Stream (.strm) File        \n");
    printf("=========================================\n");

    char strm_path[256];
    prompt_string("Enter path to .strm file", "stream.strm", strm_path, sizeof(strm_path));

    strm_stream_t stream;
    strm_init(&stream, 2);

    if (!strm_load_file(strm_path, &stream)) {
        printf("[!] Failed to load stream file '%s'\n", strm_path);
        strm_free(&stream);
        return;
    }

    printf("\n[+] Loaded stream file '%s':\n", strm_path);
    strm_print_info(&stream);

    char tx_choice[16];
    prompt_string("\nTransmit stream now? (y/n)", "y", tx_choice, sizeof(tx_choice));
    if (strcasecmp(tx_choice, "y") == 0 || strcasecmp(tx_choice, "yes") == 0) {
        prompt_transmission(&stream);
    }

    strm_free(&stream);
}

void cli_run_interactive(void) {
    while (1) {
        printf("\n=========================================\n");
        printf("   pktx v%s - Network Equipment Tool     \n", PKTX_VERSION_STR);
        printf("   Author: %s                      \n", PKTX_AUTHOR_STR);
        printf("=========================================\n");
        printf("  1. Construct & Transmit L2 Ethernet Packet\n");
        printf("  2. Construct & Transmit L3 IPv4 Packet\n");
        printf("  3. Construct & Transmit ARP Packet\n");
        printf("  4. Parse & Edit Wireshark .pcap/.pcapng File\n");
        printf("  5. Load & Transmit Saved .strm File\n");
        printf("  6. List Network Interfaces\n");
        printf("  7. Exit\n");

        uint32_t choice = prompt_uint("Select an option", 1, 1, 7);

        switch (choice) {
            case 1: build_l2_interactive(); break;
            case 2: build_l3_interactive(); break;
            case 3: build_arp_interactive(); break;
            case 4: parse_pcap_interactive(); break;
            case 5: load_strm_interactive(); break;
            case 6: list_network_interfaces(); break;
            case 7:
                printf("\nExiting pktx. Goodbye!\n");
                return;
        }
    }
}

int cli_run_args(int argc, char *argv[]) {
    static struct option long_options[] = {
        {"version",      no_argument,       0, 'v'},
        {"help",         no_argument,       0, 'h'},
        {"interactive",  no_argument,       0, 'i'},
        {"l2",           no_argument,       0, '2'},
        {"l3",           no_argument,       0, '3'},
        {"arp",          no_argument,       0, 'a'},
        {"opcode",       required_argument, 0, 'A'},
        {"src-mac",      required_argument, 0, 's'},
        {"dst-mac",      required_argument, 0, 'd'},
        {"ethertype",    required_argument, 0, 'e'},
        {"src-ip",       required_argument, 0, 'S'},
        {"dst-ip",       required_argument, 0, 'D'},
        {"sender-mac",   required_argument, 0, 'm'},
        {"sender-ip",    required_argument, 0, 'I'},
        {"target-mac",   required_argument, 0, 'M'},
        {"target-ip",    required_argument, 0, 'T'},
        {"ttl",          required_argument, 0, 't'},
        {"proto",        required_argument, 0, 'P'},
        {"size",         required_argument, 0, 'z'},
        {"payload",      required_argument, 0, 'y'},
        {"payload-file", required_argument, 0, 'F'},
        {"save",         required_argument, 0, 'o'},
        {"load",         required_argument, 0, 'l'},
        {"pcap",         required_argument, 0, 'p'},
        {"tx",           required_argument, 0, 'x'},
        {"count",        required_argument, 0, 'c'},
        {"delay",        required_argument, 0, 'w'},
        {"dry-run",      no_argument,       0, 'n'},
        {0, 0, 0, 0}
    };

    bool is_l2 = false, is_l3 = false, is_arp = false;
    uint32_t opcode = ARP_OP_REQUEST;
    char src_mac_str[32] = "00:11:22:33:44:55";
    char dst_mac_str[32] = "FF:FF:FF:FF:FF:FF";
    char ethertype_str[32] = "0x0800";
    char src_ip_str[32] = "192.168.1.100";
    char dst_ip_str[32] = "192.168.1.1";

    char sender_mac_str[32] = "00:11:22:33:44:55";
    char sender_ip_str[32]  = "192.168.1.100";
    char target_mac_str[32] = "00:00:00:00:00:00";
    char target_ip_str[32]  = "192.168.1.1";

    uint32_t ttl = 64;
    uint32_t proto = IP_PROTO_UDP;
    uint32_t pkt_size = 64;
    payload_type_t payload_type = PAYLOAD_ALL_ZEROS;
    char payload_file_path[256] = "";

    char save_path[256] = "";
    char load_path[256] = "";
    char pcap_path[256] = "";
    char tx_ifname[256] = "";
    uint32_t count = 1;
    uint32_t delay_ms = 0;
    bool dry_run = false;

    int opt, option_index = 0;
    while ((opt = getopt_long(argc, argv, "vhi23aA:s:d:e:S:D:m:I:M:T:t:P:z:y:F:o:l:p:x:c:w:n", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'v':
                printf("pktx v%s by %s\n", PKTX_VERSION_STR, PKTX_AUTHOR_STR);
                return 0;

            case 'h':
                printf("pktx v%s - Network Equipment Packet Tx & Test Tool\n", PKTX_VERSION_STR);
                printf("Author: %s\n\n", PKTX_AUTHOR_STR);
                printf("Usage: %s [OPTIONS]\n", argv[0]);
                printf("Options:\n");
                printf("  -v, --version              Display version and author info\n");
                printf("  -i, --interactive          Run in interactive menu wizard mode\n");
                printf("  -2, --l2                   Construct L2 Ethernet packet\n");
                printf("  -3, --l3                   Construct L3 IPv4 packet\n");
                printf("  -a, --arp                  Construct ARP packet\n");
                printf("  -A, --opcode OP            ARP Opcode (1=Request, 2=Reply)\n");
                printf("  -s, --src-mac MAC          Source MAC address (default: 00:11:22:33:44:55)\n");
                printf("  -d, --dst-mac MAC          Destination MAC address (default: FF:FF:FF:FF:FF:FF)\n");
                printf("  -e, --ethertype HEX        EtherType (default: 0x0800)\n");
                printf("  -S, --src-ip IP            Source IPv4 address (default: 192.168.1.100)\n");
                printf("  -D, --dst-ip IP            Destination IPv4 address (default: 192.168.1.1)\n");
                printf("  -m, --sender-mac MAC       ARP Sender MAC address\n");
                printf("  -I, --sender-ip IP         ARP Sender IPv4 address\n");
                printf("  -M, --target-mac MAC       ARP Target MAC address\n");
                printf("  -T, --target-ip IP         ARP Target IPv4 address\n");
                printf("  -t, --ttl NUM              Time To Live (default: 64)\n");
                printf("  -P, --proto NUM            IP Protocol (1=ICMP, 6=TCP, 17=UDP, default: 17)\n");
                printf("  -z, --size NUM             Total packet size 64-1514 bytes (default: 64)\n");
                printf("  -y, --payload TYPE         Payload type: zeros|ones|rand|file (default: zeros)\n");
                printf("  -F, --payload-file FILE    Path to binary file for payload\n");
                printf("  -o, --save FILE.strm       Save generated stream to .strm file\n");
                printf("  -l, --load FILE.strm       Load stream from .strm file\n");
                printf("  -p, --pcap FILE.pcapng     Parse Wireshark .pcap or .pcapng file\n");
                printf("  -x, --tx IFACE             Transmit stream on network interface (e.g. eth0, lo)\n");
                printf("  -c, --count NUM            Repetition count (default: 1)\n");
                printf("  -w, --delay MS             Inter-Packet Gap / delay in ms (default: 0)\n");
                printf("  -n, --dry-run              Simulate packet transmission without sending\n");
                return 0;

            case 'i': cli_run_interactive(); return 0;
            case '2': is_l2 = true; break;
            case '3': is_l3 = true; break;
            case 'a': is_arp = true; break;
            case 'A':
                if (strcasecmp(optarg, "reply") == 0 || strcmp(optarg, "2") == 0) opcode = ARP_OP_REPLY;
                else opcode = ARP_OP_REQUEST;
                break;
            case 's': strncpy(src_mac_str, optarg, sizeof(src_mac_str)-1); break;
            case 'd': strncpy(dst_mac_str, optarg, sizeof(dst_mac_str)-1); break;
            case 'e': strncpy(ethertype_str, optarg, sizeof(ethertype_str)-1); break;
            case 'S': strncpy(src_ip_str, optarg, sizeof(src_ip_str)-1); break;
            case 'D': strncpy(dst_ip_str, optarg, sizeof(dst_ip_str)-1); break;
            case 'm': strncpy(sender_mac_str, optarg, sizeof(sender_mac_str)-1); break;
            case 'I': strncpy(sender_ip_str, optarg, sizeof(sender_ip_str)-1); break;
            case 'M': strncpy(target_mac_str, optarg, sizeof(target_mac_str)-1); break;
            case 'T': strncpy(target_ip_str, optarg, sizeof(target_ip_str)-1); break;
            case 't': parse_uint(optarg, 1, 255, &ttl); break;
            case 'P': parse_uint(optarg, 0, 255, &proto); break;
            case 'z': parse_uint(optarg, PKTX_MIN_PACKET_SIZE, PKTX_MAX_PACKET_SIZE, &pkt_size); break;
            case 'y':
                if (strncasecmp(optarg, "file:", 5) == 0) {
                    payload_type = PAYLOAD_FILE;
                    strncpy(payload_file_path, optarg + 5, sizeof(payload_file_path) - 1);
                } else if (strcasecmp(optarg, "file") == 0 || strcmp(optarg, "4") == 0) {
                    payload_type = PAYLOAD_FILE;
                } else if (strcasecmp(optarg, "ones") == 0 || strcmp(optarg, "1") == 0) {
                    payload_type = PAYLOAD_ALL_ONES;
                } else if (strcasecmp(optarg, "rand") == 0 || strcasecmp(optarg, "random") == 0) {
                    payload_type = PAYLOAD_PSEUDO_RANDOM;
                } else {
                    payload_type = PAYLOAD_ALL_ZEROS;
                }
                break;
            case 'F':
                payload_type = PAYLOAD_FILE;
                strncpy(payload_file_path, optarg, sizeof(payload_file_path) - 1);
                break;
            case 'o': strncpy(save_path, optarg, sizeof(save_path)-1); break;
            case 'l': strncpy(load_path, optarg, sizeof(load_path)-1); break;
            case 'p': strncpy(pcap_path, optarg, sizeof(pcap_path)-1); break;
            case 'x': {
                uint32_t idx_val;
                if (parse_uint(optarg, 1, 100, &idx_val)) {
                    if_list_t if_list;
                    get_network_interfaces(&if_list);
                    if (idx_val >= 1 && idx_val <= if_list.count) {
                        strncpy(tx_ifname, if_list.interfaces[idx_val - 1].name, sizeof(tx_ifname) - 1);
                    } else {
                        strncpy(tx_ifname, optarg, sizeof(tx_ifname) - 1);
                    }
                } else {
                    strncpy(tx_ifname, optarg, sizeof(tx_ifname) - 1);
                }
                break;
            }
            case 'c': parse_uint(optarg, 0, 1000000, &count); break;
            case 'w': parse_uint(optarg, 0, 60000, &delay_ms); break;
            case 'n': dry_run = true; break;
        }
    }

    if (argc == 1) {
        cli_run_interactive();
        return 0;
    }

    strm_stream_t stream;
    strm_init(&stream, is_l3 ? 3 : 2);

    if (strlen(load_path) > 0) {
        if (!strm_load_file(load_path, &stream)) {
            fprintf(stderr, "Error loading .strm file '%s'\n", load_path);
            return 1;
        }
        strm_print_info(&stream);
    } else if (strlen(pcap_path) > 0) {
        if (!parse_pcap_or_pcapng_file(pcap_path, &stream)) {
            fprintf(stderr, "Error parsing PCAP file '%s'\n", pcap_path);
            return 1;
        }
        strm_print_info(&stream);
    } else if (is_l2 || is_l3 || is_arp) {
        uint8_t pkt_buf[PKTX_MAX_PACKET_SIZE];
        size_t built_len = 0;

        if (is_arp) {
            arp_config_t cfg;
            arp_config_set_defaults(&cfg, (uint16_t)opcode);
            parse_mac_address(src_mac_str, cfg.src_mac);
            parse_mac_address(dst_mac_str, cfg.dst_mac);
            parse_mac_address(sender_mac_str, cfg.sender_mac);
            parse_mac_address(target_mac_str, cfg.target_mac);
            parse_ipv4_address(sender_ip_str, &cfg.sender_ip);
            parse_ipv4_address(target_ip_str, &cfg.target_ip);
            cfg.total_length = pkt_size;
            cfg.payload_type = payload_type;
            strncpy(cfg.payload_file_path, payload_file_path, sizeof(cfg.payload_file_path) - 1);
            built_len = build_arp_packet(&cfg, pkt_buf, sizeof(pkt_buf));
        } else if (is_l3) {
            ipv4_config_t cfg;
            ipv4_config_set_defaults(&cfg);
            parse_mac_address(src_mac_str, cfg.src_mac);
            parse_mac_address(dst_mac_str, cfg.dst_mac);
            parse_ipv4_address(src_ip_str, &cfg.src_ip);
            parse_ipv4_address(dst_ip_str, &cfg.dst_ip);
            cfg.ttl = (uint8_t)ttl;
            cfg.protocol = (uint8_t)proto;
            cfg.total_length = pkt_size;
            cfg.payload_type = payload_type;
            strncpy(cfg.payload_file_path, payload_file_path, sizeof(cfg.payload_file_path) - 1);
            built_len = build_ipv4_packet(&cfg, pkt_buf, sizeof(pkt_buf));
        } else {
            eth_config_t cfg;
            eth_config_set_defaults(&cfg);
            parse_mac_address(src_mac_str, cfg.src_mac);
            parse_mac_address(dst_mac_str, cfg.dst_mac);
            parse_hex16(ethertype_str, &cfg.ethertype);
            cfg.total_length = pkt_size;
            cfg.payload_type = payload_type;
            strncpy(cfg.payload_file_path, payload_file_path, sizeof(cfg.payload_file_path) - 1);
            built_len = build_ethernet_packet(&cfg, pkt_buf, sizeof(pkt_buf));
        }

        if (built_len > 0) {
            strm_add_packet(&stream, pkt_buf, built_len, delay_ms, count);
            strm_print_info(&stream);
        } else {
            fprintf(stderr, "Error constructing packet.\n");
            strm_free(&stream);
            return 1;
        }
    }

    if (strlen(save_path) > 0 && stream.count > 0) {
        if (strm_save_file(save_path, &stream)) {
            printf("[+] Saved packet stream to '%s'\n", save_path);
        } else {
            fprintf(stderr, "Error saving stream to '%s'\n", save_path);
        }
    }

    if (strlen(tx_ifname) > 0 && stream.count > 0) {
        tx_options_t tx_opts;
        tx_options_set_defaults(&tx_opts);
        strncpy(tx_opts.interface_name, tx_ifname, sizeof(tx_opts.interface_name)-1);
        tx_opts.count = count;
        tx_opts.delay_ms = delay_ms;
        tx_opts.dry_run = dry_run;
        transmit_stream(&stream, &tx_opts);
    }

    strm_free(&stream);
    return 0;
}
