#ifndef PKTX_STRM_H
#define PKTX_STRM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define STRM_MAGIC 0x504B5458 // "PKTX"

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;          // STRM_MAGIC
    uint16_t version;        // Format version (1)
    uint16_t protocol_level; // 2 (L2) or 3 (L3)
    uint32_t num_packets;    // Number of packet stream entries
    uint32_t reserved;       // Reserved for future use
} strm_file_hdr_t;

typedef struct {
    uint32_t pkt_len;     // Frame length in bytes (64..1514)
    uint32_t delay_ms;    // Inter-packet gap / delay in ms
    uint32_t repetitions; // Repetition count
} strm_pkt_entry_hdr_t;
#pragma pack(pop)

typedef struct {
    uint32_t delay_ms;
    uint32_t repetitions;
    size_t pkt_len;
    uint8_t *raw_data;
} strm_entry_t;

typedef struct {
    uint16_t protocol_level; // 2 (L2) or 3 (L3)
    size_t count;
    strm_entry_t *entries;
} strm_stream_t;

// Initialize empty stream container
void strm_init(strm_stream_t *stream, uint16_t protocol_level);

// Free all allocated memory in stream container
void strm_free(strm_stream_t *stream);

// Add raw packet buffer into stream container
bool strm_add_packet(strm_stream_t *stream, const uint8_t *pkt_data, size_t pkt_len, uint32_t delay_ms, uint32_t repetitions);

// Save stream container to file in .strm format
bool strm_save_file(const char *filepath, const strm_stream_t *stream);

// Load .strm file into stream container
bool strm_load_file(const char *filepath, strm_stream_t *stream);

// Display summary of .strm stream contents
void strm_print_info(const strm_stream_t *stream);

#endif // PKTX_STRM_H
