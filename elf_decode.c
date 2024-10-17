#include <stdio.h>
#include <stdlib.h>
#include "decoder.h"

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s input_filename output_filename\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *input_filename = argv[1];
    const char *output_filename = argv[2];

    decode_elf(input_filename, output_filename);

    return 0;
}
