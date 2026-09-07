#ifndef PKTX_TRANSMITTER_H
#define PKTX_TRANSMITTER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "strm.h"

typedef struct {
    char interface_name[32]; // e.g. "eth0", "wlan0", "lo"
    uint32_t count;          // Repetitions per packet entry (0 = loop indefinitely)
    uint32_t delay_ms;       // IPG / delay between packets in ms (0 = minimal IPG)
    bool dry_run;            // If true, simulate transmission without sending to raw socket
} tx_options_t;

// Set default transmission options
void tx_options_set_defaults(tx_options_t *opts);

// List available network interfaces on system
void list_network_interfaces(void);

// Transmit single packet over specified network interface
bool transmit_packet(const char *ifname, const uint8_t *pkt_data, size_t pkt_len, bool dry_run);

// Transmit entire stream container according to stream entries and tx options
bool transmit_stream(const strm_stream_t *stream, const tx_options_t *opts);

#endif // PKTX_TRANSMITTER_H
