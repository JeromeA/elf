#include <stdlib.h>
#include "elf.h"

void free_elf_binary(ElfBinary *binary) {
    if (binary->phdrs != NULL) {
        free(binary->phdrs);
        binary->phdrs = NULL;
    }
    if (binary->shdrs != NULL) {
        free(binary->shdrs);
        binary->shdrs = NULL;
    }
    if (binary->shstrtab != NULL) {
        free(binary->shstrtab);
        binary->shstrtab = NULL;
    }
    if (binary->section_names) {
        for (int i = 0; i < binary->ehdr.e_shnum; i++) {
            free(binary->section_names[i]);
        }
        free(binary->section_names);
        binary->section_names = NULL;
    }
    if (binary->section_data) {
        for (int i = 0; i < binary->ehdr.e_shnum; i++) {
            free(binary->section_data[i]);
        }
        free(binary->section_data);
        binary->section_data = NULL;
    }
}

