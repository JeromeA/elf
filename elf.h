#ifndef ELF_H
#define ELF_H

#include <elf.h>

/* Structure representing the binary, containing ELF header and program headers */
typedef struct {
    Elf64_Ehdr ehdr;
    Elf64_Phdr *phdrs;
} ElfBinary;

/* Function to free allocated memory in ElfBinary */
void free_elf_binary(ElfBinary *binary);

#endif /* ELF_H */