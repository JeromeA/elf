#include "elf_writer.h"
#include <stdio.h>
#include <stdlib.h>

void write_elf_binary(const ElfBinary *binary, const char *output_filename) {
    FILE *fp = fopen(output_filename, "wb");
    if (!fp) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    fwrite(&binary->ehdr, sizeof(Elf64_Ehdr), 1, fp);
    fwrite(binary->phdrs, sizeof(Elf64_Phdr), binary->ehdr.e_phnum, fp);

    fclose(fp);
}
