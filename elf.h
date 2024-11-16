#ifndef ELF_H
#define ELF_H

#include <elf.h>
#include <stddef.h>

/* Structure representing the binary, containing ELF header and program headers */
typedef struct {
    Elf64_Ehdr ehdr;
    Elf64_Phdr *phdrs;
    Elf64_Shdr *shdrs;
    unsigned char **section_data;
} ElfBinary;

/* Function to free allocated memory in ElfBinary */
void free_elf_binary(ElfBinary *binary);

const char *get_section_name(const ElfBinary *binary, const Elf64_Shdr *shdr);

#endif /* ELF_H */
