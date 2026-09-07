#include "transmitter.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

static bool wsa_initialized = false;

static void ensure_wsa_init(void) {
    if (!wsa_initialized) {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) == 0) {
            wsa_initialized = true;
        }
    }
}
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#endif

void tx_options_set_defaults(tx_options_t *opts) {
    if (!opts) return;
#ifdef _WIN32
    strncpy(opts->interface_name, "Ethernet", sizeof(opts->interface_name) - 1);
#else
    strncpy(opts->interface_name, "lo", sizeof(opts->interface_name) - 1);
#endif
    opts->count = 1;
    opts->delay_ms = 0; // Minimal IPG
    opts->dry_run = false;
}

void list_network_interfaces(void) {
    printf("=== Available Network Interfaces ===\n");
#ifdef _WIN32
    ensure_wsa_init();
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
    ULONG outBufLen = 15360;
    IP_ADAPTER_ADDRESSES *pAddresses = (IP_ADAPTER_ADDRESSES *)malloc(outBufLen);

    if (pAddresses && GetAdaptersAddresses(AF_UNSPEC, flags, NULL, pAddresses, &outBufLen) == NO_ERROR) {
        for (IP_ADAPTER_ADDRESSES *pCurr = pAddresses; pCurr; pCurr = pCurr->Next) {
            wprintf(L"  - Interface: %s (Friendly: %s)\n", pCurr->AdapterName, pCurr->FriendlyName);
        }
        free(pAddresses);
    } else {
        if (pAddresses) free(pAddresses);
        printf("  - Local Loopback / Generic Network Adapter\n");
    }
#else
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return;
    }
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (ifa->ifa_addr->sa_family == AF_PACKET) {
            printf("  - Interface: %s\n", ifa->ifa_name);
        }
    }
    freeifaddrs(ifaddr);
#endif
}

bool transmit_packet(const char *ifname, const uint8_t *pkt_data, size_t pkt_len, bool dry_run) {
    if (!pkt_data || pkt_len == 0) return false;

    if (dry_run) {
        printf("[DRY-RUN] Transmitted packet (%zu bytes) on interface '%s'\n", pkt_len, ifname ? ifname : "sim0");
        return true;
    }

    if (!ifname || strlen(ifname) == 0) {
        fprintf(stderr, "Error: Interface name not specified.\n");
        return false;
    }

#ifdef _WIN32
    ensure_wsa_init();
    printf("[Windows] Raw L2 socket transmission requires Npcap / WinPcap driver on Windows.\n");
    printf("[Windows] Simulating transmission of packet (%zu bytes) on interface '%s'\n", pkt_len, ifname);
    return true;
#else
    int raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_sock < 0) {
        if (errno == EPERM || errno == EACCES) {
            fprintf(stderr, "Error: Raw socket creation requires root/sudo privileges (CAP_NET_RAW).\n");
            fprintf(stderr, "Hint: Run with 'sudo ./pktx ...' or use dry-run mode (--dry-run).\n");
        } else {
            perror("socket(AF_PACKET)");
        }
        return false;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(raw_sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl(SIOCGIFINDEX)");
        close(raw_sock);
        return false;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    ssize_t sent = sendto(raw_sock, pkt_data, pkt_len, 0, (struct sockaddr *)&sll, sizeof(sll));
    close(raw_sock);

    if (sent < 0) {
        perror("sendto(AF_PACKET)");
        return false;
    }

    return (size_t)sent == pkt_len;
#endif
}

bool transmit_stream(const strm_stream_t *stream, const tx_options_t *opts) {
    if (!stream || stream->count == 0 || !opts) {
        fprintf(stderr, "Error: Empty stream or invalid transmission options.\n");
        return false;
    }

    printf("\n>>> Transmitting stream (%zu entry/entries) on interface '%s' <<<\n",
           stream->count, opts->interface_name);
    if (opts->dry_run) {
        printf("Mode: DRY-RUN SIMULATION (No actual packets on wire)\n");
    }

    size_t total_sent = 0;
    uint32_t run_count = opts->count;
    if (run_count == 0) run_count = 1;

    for (uint32_t r = 0; r < run_count; r++) {
        for (size_t i = 0; i < stream->count; i++) {
            strm_entry_t *entry = &stream->entries[i];
            uint32_t entry_reps = (entry->repetitions > 0) ? entry->repetitions : 1;
            uint32_t delay = (opts->delay_ms > 0) ? opts->delay_ms : entry->delay_ms;

            for (uint32_t rep = 0; rep < entry_reps; rep++) {
                bool ok = transmit_packet(opts->interface_name, entry->raw_data, entry->pkt_len, opts->dry_run);
                if (!ok) {
                    fprintf(stderr, "Transmission aborted at entry #%zu, rep #%u.\n", i + 1, rep + 1);
                    return false;
                }
                total_sent++;

                if (delay > 0) {
                    sleep_ms(delay);
                }
            }
        }
    }

    printf(">>> Successfully transmitted %zu total packet(s). <<<\n\n", total_sent);
    return true;
}
