// elf_writer.c
#include "elf_writer.h"
#include <stdio.h>

void write_elf_binary(const ElfBinary *binary) {
    fwrite(&binary->ehdr, sizeof(Elf64_Ehdr), 1, stdout);
    fwrite(binary->phdrs, sizeof(Elf64_Phdr), binary->ehdr.e_phnum, stdout);
}
