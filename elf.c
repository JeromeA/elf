#include <stdlib.h>
#include "elf.h"

void free_elf_binary(ElfBinary *binary) {
    if (binary->phdrs != NULL) {
        free(binary->phdrs);
        binary->phdrs = NULL;
    }
}

