#include "elf_defaults.h"

Elf64_Off get_default_e_phoff() {
    return sizeof(Elf64_Ehdr);
}

void compute_defaults(ElfBinary *binary) {
    if (binary->ehdr.e_phoff == 0 && binary->ehdr.e_phnum > 0) {
        binary->ehdr.e_phoff = get_default_e_phoff();
    }
}

int is_default_e_phoff(const ElfBinary *binary) {
    return binary->ehdr.e_phoff == get_default_e_phoff();
}
