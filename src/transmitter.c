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

// Dynamic Npcap / WinPcap function pointer types
typedef void pcap_t;
typedef struct pcap_if {
    struct pcap_if *next;
    char *name;
    char *description;
    void *addresses;
    uint32_t flags;
} pcap_if_t;

typedef pcap_t* (*pcap_open_live_fn)(const char *, int, int, int, char *);
typedef int (*pcap_sendpacket_fn)(pcap_t *, const unsigned char *, int);
typedef void (*pcap_close_fn)(pcap_t *);
typedef int (*pcap_findalldevs_fn)(pcap_if_t **, char *);
typedef void (*pcap_freealldevs_fn)(pcap_if_t *);

static HMODULE h_wpcap = NULL;
static pcap_open_live_fn pfn_pcap_open_live = NULL;
static pcap_sendpacket_fn pfn_pcap_sendpacket = NULL;
static pcap_close_fn pfn_pcap_close = NULL;
static pcap_findalldevs_fn pfn_pcap_findalldevs = NULL;
static pcap_freealldevs_fn pfn_pcap_freealldevs = NULL;

static bool npcap_attempted = false;
static bool npcap_available = false;

static bool init_npcap(void) {
    if (npcap_attempted) return npcap_available;
    npcap_attempted = true;

    // Load Npcap / WinPcap wpcap.dll dynamically
    h_wpcap = LoadLibraryA("wpcap.dll");
    if (!h_wpcap) {
        // Try Npcap System directory fallback
        char npcap_dir[MAX_PATH];
        if (GetSystemDirectoryA(npcap_dir, sizeof(npcap_dir))) {
            strncat(npcap_dir, "\\Npcap\\wpcap.dll", sizeof(npcap_dir) - strlen(npcap_dir) - 1);
            h_wpcap = LoadLibraryA(npcap_dir);
        }
    }

    if (h_wpcap) {
        pfn_pcap_open_live   = (pcap_open_live_fn)GetProcAddress(h_wpcap, "pcap_open_live");
        pfn_pcap_sendpacket  = (pcap_sendpacket_fn)GetProcAddress(h_wpcap, "pcap_sendpacket");
        pfn_pcap_close       = (pcap_close_fn)GetProcAddress(h_wpcap, "pcap_close");
        pfn_pcap_findalldevs = (pcap_findalldevs_fn)GetProcAddress(h_wpcap, "pcap_findalldevs");
        pfn_pcap_freealldevs = (pcap_freealldevs_fn)GetProcAddress(h_wpcap, "pcap_freealldevs");

        if (pfn_pcap_open_live && pfn_pcap_sendpacket && pfn_pcap_close) {
            npcap_available = true;
        }
    }
    return npcap_available;
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

size_t get_network_interfaces(if_list_t *list) {
    if (!list) return 0;
    list->count = 0;

#ifdef _WIN32
    ensure_wsa_init();

    // Check if Npcap is available for device enumeration
    if (init_npcap() && pfn_pcap_findalldevs && pfn_pcap_freealldevs) {
        pcap_if_t *alldevs = NULL;
        char errbuf[256] = {0};
        if (pfn_pcap_findalldevs(&alldevs, errbuf) == 0 && alldevs) {
            for (pcap_if_t *d = alldevs; d && list->count < MAX_IF_ENTRIES; d = d->next) {
                strncpy(list->interfaces[list->count].name, d->name, sizeof(list->interfaces[list->count].name) - 1);
                snprintf(list->interfaces[list->count].description, sizeof(list->interfaces[list->count].description),
                         "%s", d->description ? d->description : "Npcap Interface");
                list->count++;
            }
            pfn_pcap_freealldevs(alldevs);
        }
    }

    // Fallback to Win32 IP Helper API if Npcap device list is empty
    if (list->count == 0) {
        ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
        ULONG outBufLen = 15360;
        IP_ADAPTER_ADDRESSES *pAddresses = (IP_ADAPTER_ADDRESSES *)malloc(outBufLen);

        if (pAddresses && GetAdaptersAddresses(AF_UNSPEC, flags, NULL, pAddresses, &outBufLen) == NO_ERROR) {
            for (IP_ADAPTER_ADDRESSES *pCurr = pAddresses; pCurr && list->count < MAX_IF_ENTRIES; pCurr = pCurr->Next) {
                char name[32];
                char desc[128];
                snprintf(name, sizeof(name), "%ls", pCurr->FriendlyName ? pCurr->FriendlyName : L"Adapter");
                snprintf(desc, sizeof(desc), "%s", pCurr->AdapterName ? pCurr->AdapterName : "");

                strncpy(list->interfaces[list->count].name, name, sizeof(list->interfaces[list->count].name) - 1);
                strncpy(list->interfaces[list->count].description, desc, sizeof(list->interfaces[list->count].description) - 1);
                list->count++;
            }
            free(pAddresses);
        }
    }
#else
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) != -1) {
        for (ifa = ifaddr; ifa != NULL && list->count < MAX_IF_ENTRIES; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == NULL) continue;
            if (ifa->ifa_addr->sa_family == AF_PACKET) {
                bool already_added = false;
                for (size_t k = 0; k < list->count; k++) {
                    if (strcmp(list->interfaces[k].name, ifa->ifa_name) == 0) {
                        already_added = true;
                        break;
                    }
                }
                if (!already_added) {
                    strncpy(list->interfaces[list->count].name, ifa->ifa_name, sizeof(list->interfaces[list->count].name) - 1);
                    snprintf(list->interfaces[list->count].description, sizeof(list->interfaces[list->count].description), "Network Interface");
                    list->count++;
                }
            }
        }
        freeifaddrs(ifaddr);
    }
#endif

    if (list->count == 0) {
        strncpy(list->interfaces[0].name, "lo", sizeof(list->interfaces[0].name) - 1);
        strncpy(list->interfaces[0].description, "Local Loopback", sizeof(list->interfaces[0].description) - 1);
        list->count = 1;
    }

    return list->count;
}

void print_network_interfaces(const if_list_t *list) {
    if (!list) return;
    printf("=== Available Network Interfaces ===\n");
    for (size_t i = 0; i < list->count; i++) {
        printf("  %zu. %s (%s)\n", i + 1, list->interfaces[i].name, list->interfaces[i].description);
    }
}

void list_network_interfaces(void) {
    if_list_t list;
    get_network_interfaces(&list);
    print_network_interfaces(&list);
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
    if (init_npcap()) {
        char errbuf[256] = {0};
        pcap_t *p = pfn_pcap_open_live(ifname, 65535, 1, 1000, errbuf);
        if (!p && strncmp(ifname, "\\Device\\", 8) != 0) {
            char devname[256];
            snprintf(devname, sizeof(devname), "\\Device\\NPF_%s", ifname);
            p = pfn_pcap_open_live(devname, 65535, 1, 1000, errbuf);
        }

        if (p) {
            int ret = pfn_pcap_sendpacket(p, pkt_data, (int)pkt_len);
            pfn_pcap_close(p);
            if (ret == 0) {
                printf("[Windows Npcap] Transmitted packet (%zu bytes) on wire via interface '%s'\n", pkt_len, ifname);
                return true;
            } else {
                fprintf(stderr, "[Windows Npcap] Error sending packet on interface '%s'\n", ifname);
                return false;
            }
        } else {
            fprintf(stderr, "[Windows Npcap] Unable to open interface '%s': %s\n", ifname, errbuf);
            return false;
        }
    } else {
        printf("[Windows Notice] Npcap / WinPcap driver (wpcap.dll) is not installed on this Windows system.\n");
        printf("  - To transmit live raw Ethernet packets on physical network interfaces, install free Npcap driver from https://npcap.com/\n");
        printf("  - Simulating transmission of packet (%zu bytes) on interface '%s'\n", pkt_len, ifname);
        return true;
    }
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
