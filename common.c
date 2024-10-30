
#include "common.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

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

void *xcrealloc(void * ptr, size_t old_size, size_t new_size) {
    void *new_ptr = realloc(ptr, new_size);
    if (new_ptr == NULL) {
        perror("realloc failed");
        exit(EXIT_FAILURE);
    }
    if (new_size > old_size) {
        memset((char *)new_ptr + old_size, 0, new_size - old_size);
    }
    return new_ptr;
}
