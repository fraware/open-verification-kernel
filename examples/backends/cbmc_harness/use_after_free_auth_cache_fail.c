#include <assert.h>
#include <stdlib.h>
#include <stdint.h>

void harness(void) {
    int *entry = (int *)malloc(sizeof(int));
    free(entry);
    *entry = 1;
    assert(entry != NULL);
}
