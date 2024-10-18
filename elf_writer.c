#include "elf_writer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void write_elf_binary(ElfBinary *binary, const char *output_filename) {
    FILE *fp = fopen(output_filename, "wb");
    if (!fp) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    // Write ELF header
    fseek(fp, 0, SEEK_SET);
    fwrite(&binary->ehdr, sizeof(Elf64_Ehdr), 1, fp);

    // Write program headers if any
    if (binary->ehdr.e_phnum > 0) {
        fseek(fp, binary->ehdr.e_phoff, SEEK_SET);
        fwrite(binary->phdrs, sizeof(Elf64_Phdr), binary->ehdr.e_phnum, fp);
    }

    // Write section data
    for (int i = 0; i < binary->ehdr.e_shnum; i++) {
        Elf64_Shdr *shdr = &binary->shdrs[i];
        if (shdr->sh_type != SHT_NOBITS && shdr->sh_size > 0) {
            fseek(fp, shdr->sh_offset, SEEK_SET);
            fwrite(binary->section_data[i], shdr->sh_size, 1, fp);
        }
    }

    // Write section headers
    fseek(fp, binary->ehdr.e_shoff, SEEK_SET);
    fwrite(binary->shdrs, sizeof(Elf64_Shdr), binary->ehdr.e_shnum, fp);

    fclose(fp);
}
