#include "strm.h"
#include "utils.h"
#include "ethernet.h"
#include "ipv4.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void strm_init(strm_stream_t *stream, uint16_t protocol_level) {
    if (!stream) return;
    stream->protocol_level = protocol_level;
    stream->count = 0;
    stream->entries = NULL;
}

void strm_free(strm_stream_t *stream) {
    if (!stream) return;
    if (stream->entries) {
        for (size_t i = 0; i < stream->count; i++) {
            if (stream->entries[i].raw_data) {
                free(stream->entries[i].raw_data);
            }
        }
        free(stream->entries);
        stream->entries = NULL;
    }
    stream->count = 0;
}

bool strm_add_packet(strm_stream_t *stream, const uint8_t *pkt_data, size_t pkt_len, uint32_t delay_ms, uint32_t repetitions) {
    if (!stream || !pkt_data || pkt_len < PKTX_MIN_PACKET_SIZE || pkt_len > PKTX_MAX_PACKET_SIZE) return false;

    strm_entry_t *new_entries = realloc(stream->entries, (stream->count + 1) * sizeof(strm_entry_t));
    if (!new_entries) return false;

    stream->entries = new_entries;
    strm_entry_t *entry = &stream->entries[stream->count];
    entry->pkt_len = pkt_len;
    entry->delay_ms = delay_ms;
    entry->repetitions = (repetitions == 0) ? 1 : repetitions;

    entry->raw_data = malloc(pkt_len);
    if (!entry->raw_data) return false;
    memcpy(entry->raw_data, pkt_data, pkt_len);

    stream->count++;
    return true;
}

bool strm_save_file(const char *filepath, const strm_stream_t *stream) {
    if (!filepath || !stream) return false;

    char clean_path[512];
    strncpy(clean_path, filepath, sizeof(clean_path) - 1);
    clean_path[sizeof(clean_path) - 1] = '\0';
    ensure_strm_extension(clean_path, sizeof(clean_path));

    FILE *f = fopen(clean_path, "wb");
    if (!f) return false;

    strm_file_hdr_t file_hdr;
    file_hdr.magic = STRM_MAGIC;
    file_hdr.version = 1;
    file_hdr.protocol_level = stream->protocol_level;
    file_hdr.num_packets = (uint32_t)stream->count;
    file_hdr.reserved = 0;

    if (fwrite(&file_hdr, sizeof(file_hdr), 1, f) != 1) {
        fclose(f);
        return false;
    }

    for (size_t i = 0; i < stream->count; i++) {
        strm_entry_t *entry = &stream->entries[i];
        strm_pkt_entry_hdr_t pkt_hdr;
        pkt_hdr.pkt_len = (uint32_t)entry->pkt_len;
        pkt_hdr.delay_ms = entry->delay_ms;
        pkt_hdr.repetitions = entry->repetitions;

        if (fwrite(&pkt_hdr, sizeof(pkt_hdr), 1, f) != 1) {
            fclose(f);
            return false;
        }
        if (fwrite(entry->raw_data, 1, entry->pkt_len, f) != entry->pkt_len) {
            fclose(f);
            return false;
        }
    }

    fclose(f);
    return true;
}

bool strm_load_file(const char *filepath, strm_stream_t *stream) {
    if (!filepath || !stream) return false;

    char clean_path[512];
    strncpy(clean_path, filepath, sizeof(clean_path) - 1);
    clean_path[sizeof(clean_path) - 1] = '\0';
    ensure_strm_extension(clean_path, sizeof(clean_path));

    FILE *f = fopen(clean_path, "rb");
    if (!f) return false;

    strm_file_hdr_t file_hdr;
    if (fread(&file_hdr, sizeof(file_hdr), 1, f) != 1) {
        fclose(f);
        return false;
    }

    if (file_hdr.magic != STRM_MAGIC) {
        fclose(f);
        return false;
    }

    strm_free(stream);
    strm_init(stream, file_hdr.protocol_level);

    for (uint32_t i = 0; i < file_hdr.num_packets; i++) {
        strm_pkt_entry_hdr_t pkt_hdr;
        if (fread(&pkt_hdr, sizeof(pkt_hdr), 1, f) != 1) {
            strm_free(stream);
            fclose(f);
            return false;
        }

        if (pkt_hdr.pkt_len < PKTX_MIN_PACKET_SIZE || pkt_hdr.pkt_len > PKTX_MAX_PACKET_SIZE) {
            strm_free(stream);
            fclose(f);
            return false;
        }

        uint8_t *buf = malloc(pkt_hdr.pkt_len);
        if (!buf) {
            strm_free(stream);
            fclose(f);
            return false;
        }

        if (fread(buf, 1, pkt_hdr.pkt_len, f) != pkt_hdr.pkt_len) {
            free(buf);
            strm_free(stream);
            fclose(f);
            return false;
        }

        strm_add_packet(stream, buf, pkt_hdr.pkt_len, pkt_hdr.delay_ms, pkt_hdr.repetitions);
        free(buf);
    }

    fclose(f);
    return true;
}

#include "arp.h"

void strm_print_info(const strm_stream_t *stream) {
    if (!stream) return;
    printf("=== Stream (.strm) Information ===\n");
    printf("  Protocol Level : L%u\n", stream->protocol_level);
    printf("  Packet Count   : %zu\n", stream->count);

    for (size_t i = 0; i < stream->count; i++) {
        strm_entry_t *e = &stream->entries[i];
        printf("\n-- Stream Entry #%zu --\n", i + 1);
        printf("  Packet Size  : %zu bytes\n", e->pkt_len);
        printf("  Repetitions  : %u\n", e->repetitions);
        printf("  Delay (IPG)  : %u ms\n", e->delay_ms);

        eth_hdr_t eth;
        if (parse_ethernet_header(e->raw_data, e->pkt_len, &eth, NULL, NULL)) {
            print_ethernet_header(&eth, e->pkt_len);
            if (eth.ethertype == ETHER_TYPE_IPV4) {
                ipv4_hdr_t ip;
                if (parse_ipv4_header(e->raw_data, e->pkt_len, &ip, NULL, NULL)) {
                    print_ipv4_header(&ip);
                }
            } else if (eth.ethertype == ETHER_TYPE_ARP) {
                arp_hdr_t arp;
                if (parse_arp_header(e->raw_data, e->pkt_len, &arp, NULL, NULL)) {
                    print_arp_header(&arp);
                }
            }
        }
    }
}
