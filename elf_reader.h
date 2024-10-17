#ifndef ELF_READER_H
#define ELF_READER_H

#include "elf.h"

void read_elf_binary(const char *filename, ElfBinary *binary);

#endif /* ELF_READER_H */
