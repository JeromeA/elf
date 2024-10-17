#ifndef ELF_WRITER_H
#define ELF_WRITER_H

#include "elf.h"

void write_elf_binary(const ElfBinary *binary, const char *output_filename);

#endif /* ELF_WRITER_H */
