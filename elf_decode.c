#include <stdio.h>
#include <stdlib.h>
#include "decoder.h"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s filename\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *filename = argv[1];

    decode_elf(filename);

    return 0;
}
