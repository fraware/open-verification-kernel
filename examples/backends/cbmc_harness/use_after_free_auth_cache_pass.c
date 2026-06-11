#include <assert.h>
#include <stdlib.h>
#include <stdint.h>

void harness(void) {
    int *entry = (int *)malloc(sizeof(int));
    assert(entry != NULL);
    *entry = 1;
    free(entry);
    entry = NULL;
    assert(entry == NULL);
}
