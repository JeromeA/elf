#include <stdlib.h>
#include "elf.h"

const char *
get_section_name(const ElfBinary *binary, const Elf64_Shdr *shdr) {
    unsigned char *shstrtab = binary->section_data[binary->ehdr.e_shstrndx];
    return (const char *)&shstrtab[shdr->sh_name];
}

void free_elf_binary(ElfBinary *binary) {
    if (binary->phdrs != NULL) {
        free(binary->phdrs);
        binary->phdrs = NULL;
    }
    if (binary->shdrs != NULL) {
        free(binary->shdrs);
        binary->shdrs = NULL;
    }
    if (binary->section_data) {
        for (int i = 0; i < binary->ehdr.e_shnum; i++) {
            free(binary->section_data[i]);
        }
        free(binary->section_data);
        binary->section_data = NULL;
    }
}

