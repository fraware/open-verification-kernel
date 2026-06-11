#include <assert.h>
#include <stdint.h>

#define BUFFER_SIZE 16

void harness(void) {
    uint8_t buffer[BUFFER_SIZE];
    unsigned int index;
    __CPROVER_assume(index < BUFFER_SIZE);
    buffer[index] = 0x41U;
    assert(index < BUFFER_SIZE);
}
