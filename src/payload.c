#include "payload.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>

static int rng_seeded = 0;

void generate_payload(uint8_t *buffer, size_t size, payload_type_t type) {
    if (!buffer || size == 0) return;

    switch (type) {
        case PAYLOAD_ALL_ZEROS:
            memset(buffer, 0x00, size);
            break;

        case PAYLOAD_ALL_ONES:
            memset(buffer, 0xFF, size);
            break;

        case PAYLOAD_PSEUDO_RANDOM:
            if (!rng_seeded) {
                srand((unsigned int)time(NULL));
                rng_seeded = 1;
            }
            for (size_t i = 0; i < size; i++) {
                buffer[i] = (uint8_t)(rand() & 0xFF);
            }
            break;

        default:
            memset(buffer, 0x00, size);
            break;
    }
}

const char* payload_type_to_string(payload_type_t type) {
    switch (type) {
        case PAYLOAD_ALL_ZEROS: return "All 0s (0x00)";
        case PAYLOAD_ALL_ONES: return "All 1s (0xFF)";
        case PAYLOAD_PSEUDO_RANDOM: return "Pseudo-random";
        default: return "Unknown";
    }
}
