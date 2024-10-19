#include "elf_defaults.h"

void compute_defaults(ElfBinary *binary) {
    if (binary->ehdr.e_ehsize == 0) {
        binary->ehdr.e_ehsize = sizeof(Elf64_Ehdr);
    }
    if (binary->ehdr.e_phoff == 0 && binary->ehdr.e_phnum > 0) {
        binary->ehdr.e_phoff = sizeof(Elf64_Ehdr);
    }
    if (binary->ehdr.e_phentsize == 0 && binary->ehdr.e_phnum > 0) {
        binary->ehdr.e_phentsize = sizeof(Elf64_Phdr);
    }
    if (binary->ehdr.e_shentsize == 0 && binary->ehdr.e_shnum > 0) {
        binary->ehdr.e_shentsize = sizeof(Elf64_Shdr);
    }
}

int is_default_e_phoff(const ElfBinary *binary) {
    return binary->ehdr.e_phoff == sizeof(Elf64_Ehdr);
}

int is_default_e_phentsize(const ElfBinary *binary) {
    return binary->ehdr.e_phentsize == sizeof(Elf64_Phdr);
}

int is_default_e_shentsize(const ElfBinary *binary) {
    return binary->ehdr.e_shentsize == sizeof(Elf64_Shdr);
}
