#ifndef ELF_DEFAULTS_H
#define ELF_DEFAULTS_H

#include "elf.h"
#include <stdbool.h>

/* Computes default values for missing ELF header fields */
void compute_defaults(ElfBinary *binary);

bool is_default_section_offset(const ElfBinary *binary, int segnum, Elf64_Off offset);
bool is_default_section_addr(const ElfBinary *binary, int segnum, Elf64_Addr addr);
bool is_default_e_phoff(const ElfBinary *binary);
bool is_default_e_shoff(const ElfBinary *binary);
bool is_default_e_phentsize(const ElfBinary *binary);
bool is_default_e_shentsize(const ElfBinary *binary);
bool is_default_e_shstrndx(const ElfBinary *binary);

#endif /* ELF_DEFAULTS_H */

