#ifndef PKTX_PCAPNG_H
#define PKTX_PCAPNG_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "strm.h"

// Parse pcap or pcapng file into a stream container
bool parse_pcap_or_pcapng_file(const char *filepath, strm_stream_t *stream_out);

#endif // PKTX_PCAPNG_H
