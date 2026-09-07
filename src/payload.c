#include "payload.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

static int rng_seeded = 0;

void generate_payload_ext(uint8_t *buffer, size_t size, payload_type_t type, const char *file_path) {
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

        case PAYLOAD_FILE:
            if (file_path && strlen(file_path) > 0) {
                FILE *f = fopen(file_path, "rb");
                if (f) {
                    fseek(f, 0, SEEK_END);
                    long fsize = ftell(f);
                    fseek(f, 0, SEEK_SET);

                    if (fsize > 0) {
                        uint8_t *fbuf = malloc(fsize);
                        if (fbuf) {
                            size_t read_bytes = fread(fbuf, 1, fsize, f);
                            if (read_bytes > 0) {
                                for (size_t i = 0; i < size; i++) {
                                    buffer[i] = fbuf[i % read_bytes];
                                }
                            } else {
                                memset(buffer, 0x00, size);
                            }
                            free(fbuf);
                        } else {
                            memset(buffer, 0x00, size);
                        }
                    } else {
                        memset(buffer, 0x00, size);
                    }
                    fclose(f);
                } else {
                    fprintf(stderr, "Warning: Unable to open binary payload file '%s'. Defaulting payload to zeros.\n", file_path);
                    memset(buffer, 0x00, size);
                }
            } else {
                memset(buffer, 0x00, size);
            }
            break;

        default:
            memset(buffer, 0x00, size);
            break;
    }
}

void generate_payload(uint8_t *buffer, size_t size, payload_type_t type) {
    generate_payload_ext(buffer, size, type, NULL);
}

const char* payload_type_to_string(payload_type_t type) {
    switch (type) {
        case PAYLOAD_ALL_ZEROS: return "All 0s (0x00)";
        case PAYLOAD_ALL_ONES: return "All 1s (0xFF)";
        case PAYLOAD_PSEUDO_RANDOM: return "Pseudo-random";
        case PAYLOAD_FILE: return "Binary file";
        default: return "Unknown";
    }
}
