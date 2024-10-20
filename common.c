
#include "common.h"
#include <stdlib.h>
#include <stdio.h>

void* xmalloc(size_t size) {
    void* ptr = malloc(size);
    if (ptr == NULL) {
        perror("malloc failed");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

