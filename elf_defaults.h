#ifndef ELF_DEFAULTS_H
#define ELF_DEFAULTS_H

#include "elf.h"

/* Computes default values for missing ELF header fields */
void compute_defaults(ElfBinary *binary);

/* Checks if e_phoff is the default value */
int is_default_e_phoff(const ElfBinary *binary);

#endif /* ELF_DEFAULTS_H */

