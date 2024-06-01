#include "free.h"

void set_free(unsigned char *block, int num, int set) {
    int byte_i = num / 8;
    int bit_i = num % 8;
    block[byte_i] = (block[byte_i] & ~(1 << bit_i)) | (set << bit_i);
}

int find_free(unsigned char *block) {
    
    for (int byte = 0; byte < 4096; byte++) {
        int num = block[byte];
        if (num != 255) {
            for (int bit = 0; bit < 8; bit++) {
                if ((num & (1 << bit)) == 0) {
                    return byte * 8 + bit;
                }
            }
        }
    }
    return -1;
}

