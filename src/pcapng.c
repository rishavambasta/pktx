#include "pcapng.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PCAPNG_SHB_TYPE 0x0A0D0D0A
#define PCAPNG_IDB_TYPE 0x00000001
#define PCAPNG_EPB_TYPE 0x00000006
#define PCAPNG_SPB_TYPE 0x00000003

#define PCAP_CLASSIC_MAGIC1 0xA1B2C3D4
#define PCAP_CLASSIC_MAGIC2 0xD4C3B2A1
#define PCAP_CLASSIC_MAGIC3 0xA1B23C4D
#define PCAP_CLASSIC_MAGIC4 0x4D3CB2A1

static uint32_t swap32(uint32_t val) {
    return ((val & 0x000000FF) << 24) |
           ((val & 0x0000FF00) << 8)  |
           ((val & 0x00FF0000) >> 8)  |
           ((val & 0xFF000000) >> 24);
}

static bool parse_classic_pcap(FILE *f, strm_stream_t *stream, bool need_swap) {
    // Read remaining 20 bytes of 24-byte classic pcap header
    uint8_t hdr_rest[20];
    if (fread(hdr_rest, 1, 20, f) != 20) return false;

    while (!feof(f)) {
        uint32_t pkt_hdr[4]; // ts_sec, ts_usec, incl_len, orig_len
        if (fread(pkt_hdr, 4, 4, f) != 4) break;

        uint32_t incl_len = need_swap ? swap32(pkt_hdr[2]) : pkt_hdr[2];

        if (incl_len == 0 || incl_len > 65535) break;

        uint8_t *pkt_buf = malloc(incl_len);
        if (!pkt_buf) break;

        if (fread(pkt_buf, 1, incl_len, f) != incl_len) {
            free(pkt_buf);
            break;
        }

        // Clip/pad to 64..1514 if necessary for stream
        size_t final_len = incl_len;
        if (final_len > PKTX_MAX_PACKET_SIZE) final_len = PKTX_MAX_PACKET_SIZE;

        if (final_len >= PKTX_MIN_PACKET_SIZE) {
            strm_add_packet(stream, pkt_buf, final_len, 0, 1);
        } else {
            // Pad small packet to 64 bytes
            uint8_t padded[PKTX_MIN_PACKET_SIZE];
            memset(padded, 0, sizeof(padded));
            memcpy(padded, pkt_buf, final_len);
            strm_add_packet(stream, padded, PKTX_MIN_PACKET_SIZE, 0, 1);
        }

        free(pkt_buf);
    }
    return stream->count > 0;
}

static bool parse_pcapng(FILE *f, strm_stream_t *stream) {
    rewind(f);
    bool need_swap = false;

    while (!feof(f)) {
        uint32_t block_type = 0;
        uint32_t block_tot_len = 0;

        if (fread(&block_type, 4, 1, f) != 1) break;
        if (fread(&block_tot_len, 4, 1, f) != 1) break;

        if (block_type == PCAPNG_SHB_TYPE) {
            // Check byte order magic
            uint32_t bom = 0;
            if (fread(&bom, 4, 1, f) == 1) {
                if (bom == 0x1A2B3C4D) {
                    need_swap = false;
                } else if (bom == 0x4D3C2B1A) {
                    need_swap = true;
                }
            }
            uint32_t len = need_swap ? swap32(block_tot_len) : block_tot_len;
            if (len > 12) {
                fseek(f, len - 12, SEEK_CUR);
            }
            continue;
        }

        uint32_t cur_len = need_swap ? swap32(block_tot_len) : block_tot_len;
        uint32_t cur_type = need_swap ? swap32(block_type) : block_type;

        if (cur_len < 12) break; // Invalid block length

        if (cur_type == PCAPNG_EPB_TYPE) {
            // EPB Body: Interface ID (4B), Timestamp High (4B), Timestamp Low (4B), CapLen (4B), OrigLen (4B), Data
            uint32_t epb_hdr[5];
            if (fread(epb_hdr, 4, 5, f) != 5) break;

            uint32_t cap_len = need_swap ? swap32(epb_hdr[3]) : epb_hdr[3];

            if (cap_len > 0 && cap_len <= 65535) {
                uint8_t *pkt_buf = malloc(cap_len);
                if (pkt_buf) {
                    if (fread(pkt_buf, 1, cap_len, f) == cap_len) {
                        size_t final_len = cap_len;
                        if (final_len > PKTX_MAX_PACKET_SIZE) final_len = PKTX_MAX_PACKET_SIZE;

                        if (final_len >= PKTX_MIN_PACKET_SIZE) {
                            strm_add_packet(stream, pkt_buf, final_len, 0, 1);
                        } else {
                            uint8_t padded[PKTX_MIN_PACKET_SIZE];
                            memset(padded, 0, sizeof(padded));
                            memcpy(padded, pkt_buf, final_len);
                            strm_add_packet(stream, padded, PKTX_MIN_PACKET_SIZE, 0, 1);
                        }
                    }
                    free(pkt_buf);
                }
            }

            // Skip alignment padding + remaining block bytes (trailing block length 4 bytes included in total len)
            size_t bytes_read = 8 + 20 + cap_len;
            if (cur_len > bytes_read) {
                fseek(f, cur_len - bytes_read, SEEK_CUR);
            }
        } else if (cur_type == PCAPNG_SPB_TYPE) {
            // SPB Body: OrigLen (4B), Data
            uint32_t orig_len = 0;
            if (fread(&orig_len, 4, 1, f) != 1) break;
            orig_len = need_swap ? swap32(orig_len) : orig_len;

            uint32_t cap_len = cur_len - 16;
            if (cap_len > orig_len) cap_len = orig_len;

            if (cap_len > 0 && cap_len <= 65535) {
                uint8_t *pkt_buf = malloc(cap_len);
                if (pkt_buf) {
                    if (fread(pkt_buf, 1, cap_len, f) == cap_len) {
                        size_t final_len = cap_len;
                        if (final_len > PKTX_MAX_PACKET_SIZE) final_len = PKTX_MAX_PACKET_SIZE;

                        if (final_len >= PKTX_MIN_PACKET_SIZE) {
                            strm_add_packet(stream, pkt_buf, final_len, 0, 1);
                        } else {
                            uint8_t padded[PKTX_MIN_PACKET_SIZE];
                            memset(padded, 0, sizeof(padded));
                            memcpy(padded, pkt_buf, final_len);
                            strm_add_packet(stream, padded, PKTX_MIN_PACKET_SIZE, 0, 1);
                        }
                    }
                    free(pkt_buf);
                }
            }

            size_t bytes_read = 8 + 4 + cap_len;
            if (cur_len > bytes_read) {
                fseek(f, cur_len - bytes_read, SEEK_CUR);
            }
        } else {
            // Skip unhandled block
            fseek(f, cur_len - 8, SEEK_CUR);
        }
    }

    return stream->count > 0;
}

bool parse_pcap_or_pcapng_file(const char *filepath, strm_stream_t *stream_out) {
    if (!filepath || !stream_out) return false;

    FILE *f = fopen(filepath, "rb");
    if (!f) return false;

    uint32_t first_magic = 0;
    if (fread(&first_magic, 4, 1, f) != 1) {
        fclose(f);
        return false;
    }

    strm_init(stream_out, 2); // Default to L2

    if (first_magic == PCAP_CLASSIC_MAGIC1 || first_magic == PCAP_CLASSIC_MAGIC3) {
        bool ok = parse_classic_pcap(f, stream_out, false);
        fclose(f);
        return ok;
    } else if (first_magic == PCAP_CLASSIC_MAGIC2 || first_magic == PCAP_CLASSIC_MAGIC4) {
        bool ok = parse_classic_pcap(f, stream_out, true);
        fclose(f);
        return ok;
    } else if (first_magic == PCAPNG_SHB_TYPE) {
        bool ok = parse_pcapng(f, stream_out);
        fclose(f);
        return ok;
    }

    fclose(f);
    return false;
}
