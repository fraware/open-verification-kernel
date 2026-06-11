#include <assert.h>
#include <stdint.h>

#define QUOTA_LIMIT 1000U

void harness(void) {
    unsigned int used;
    unsigned int delta;
    __CPROVER_assume(used <= QUOTA_LIMIT);
    __CPROVER_assume(delta <= QUOTA_LIMIT);
    unsigned int next = used + delta;
    assert(next >= used);
    assert(next <= QUOTA_LIMIT);
}
