#ifndef PKTX_PAYLOAD_H
#define PKTX_PAYLOAD_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef enum {
    PAYLOAD_ALL_ZEROS = 1,
    PAYLOAD_ALL_ONES = 2,
    PAYLOAD_PSEUDO_RANDOM = 3,
    PAYLOAD_FILE = 4
} payload_type_t;

// Fill buffer with specified payload type (supports optional file path for PAYLOAD_FILE)
void generate_payload_ext(uint8_t *buffer, size_t size, payload_type_t type, const char *file_path);

// Backward compatible helper
void generate_payload(uint8_t *buffer, size_t size, payload_type_t type);

// Convert payload type enum to string description
const char* payload_type_to_string(payload_type_t type);

#endif // PKTX_PAYLOAD_H
