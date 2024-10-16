// elf.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "decoder.h"
#include "encoder.h"
#include "elf.h"

void free_elf_binary(ElfBinary *binary) {
    if (binary->phdrs != NULL) {
        free(binary->phdrs);
        binary->phdrs = NULL;
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s -e|-d filename\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *option = argv[1];
    const char *filename = argv[2];

    if (strcmp(option, "-d") == 0) {
        decode_elf(filename);
    } else if (strcmp(option, "-e") == 0) {
        encode_elf(filename);
    } else {
        fprintf(stderr, "Invalid option. Use -e for encode or -d for decode.\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}
