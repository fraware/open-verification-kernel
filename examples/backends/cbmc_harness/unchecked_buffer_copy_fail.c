#include <assert.h>
#include <stdint.h>
#include <string.h>

#define DEST_SIZE 32U

void harness(void) {
    uint8_t dest[DEST_SIZE];
    uint8_t src[DEST_SIZE];
    unsigned int length;
    memcpy(dest, src, length);
    assert(length <= DEST_SIZE);
}
