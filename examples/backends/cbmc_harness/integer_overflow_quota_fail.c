#include <assert.h>
#include <stdint.h>

#define QUOTA_LIMIT 1000U

void harness(void) {
    unsigned int used;
    unsigned int delta;
    unsigned int next = used + delta;
    assert(next >= used);
    assert(next <= QUOTA_LIMIT);
}
