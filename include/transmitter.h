#ifndef PKTX_TRANSMITTER_H
#define PKTX_TRANSMITTER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "strm.h"

#define MAX_IF_ENTRIES 32

typedef struct {
    char name[32];
    char description[128];
} if_info_t;

typedef struct {
    size_t count;
    if_info_t interfaces[MAX_IF_ENTRIES];
} if_list_t;

typedef struct {
    char interface_name[32]; // e.g. "eth0", "wlan0", "lo"
    uint32_t count;          // Repetitions per packet entry (0 = loop indefinitely)
    uint32_t delay_ms;       // IPG / delay between packets in ms (0 = minimal IPG)
    bool dry_run;            // If true, simulate transmission without sending to raw socket
} tx_options_t;

// Set default transmission options
void tx_options_set_defaults(tx_options_t *opts);

// Discover available network interfaces
size_t get_network_interfaces(if_list_t *list);

// Display numbered list of available network interfaces
void print_network_interfaces(const if_list_t *list);

// Legacy/helper function to list interfaces directly
void list_network_interfaces(void);

// Transmit single packet over specified network interface
bool transmit_packet(const char *ifname, const uint8_t *pkt_data, size_t pkt_len, bool dry_run);

// Transmit entire stream container according to stream entries and tx options
bool transmit_stream(const strm_stream_t *stream, const tx_options_t *opts);

#endif // PKTX_TRANSMITTER_H
