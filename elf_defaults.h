#ifndef ELF_DEFAULTS_H
#define ELF_DEFAULTS_H

#include "elf.h"

/* Computes default values for missing ELF header fields */
void compute_defaults(ElfBinary *binary);

int is_default_e_phoff(const ElfBinary *binary);
int is_default_e_phentsize(const ElfBinary *binary);
int is_default_e_shentsize(const ElfBinary *binary);

#endif /* ELF_DEFAULTS_H */

