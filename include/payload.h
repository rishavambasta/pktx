#ifndef PKTX_PAYLOAD_H
#define PKTX_PAYLOAD_H

#include <stdint.h>
#include <stddef.h>

typedef enum {
    PAYLOAD_ALL_ZEROS = 1,
    PAYLOAD_ALL_ONES = 2,
    PAYLOAD_PSEUDO_RANDOM = 3
} payload_type_t;

// Fill buffer with specified payload type
void generate_payload(uint8_t *buffer, size_t size, payload_type_t type);

// Convert payload type enum to string description
const char* payload_type_to_string(payload_type_t type);

#endif // PKTX_PAYLOAD_H
