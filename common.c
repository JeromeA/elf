
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

void* xcalloc(size_t nmemb, size_t size) {
    void* ptr = calloc(nmemb, size);
    if (ptr == NULL) {
        perror("calloc failed");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

void *xrealloc(void * ptr, size_t size) {
    ptr = realloc(ptr, size);
    if (ptr == NULL) {
        perror("realloc failed");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

