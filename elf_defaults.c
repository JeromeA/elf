#include "elf_defaults.h"
#include <stdio.h>
#include <string.h>

static bool is_file_only_section(const ElfBinary *binary, const Elf64_Shdr *shdr) {
    if (shdr->sh_type == SHT_NULL) return true;
    if (shdr->sh_name > 0 &&
            (strncmp(".debug", get_section_name(binary, shdr), 6) == 0 ||
             strcmp(".comment", get_section_name(binary, shdr)) == 0 ||
             strcmp(".shstrtab", get_section_name(binary, shdr)) == 0 ||
             strcmp(".strtab", get_section_name(binary, shdr)) == 0 ||
             strcmp(".symtab", get_section_name(binary, shdr)) == 0)) {
        return true;
    }
    return false;
}

static void calculate_section_offsets(const ElfBinary *binary) {
    Elf64_Off current_offset = binary->ehdr.e_ehsize + binary->ehdr.e_phnum * binary->ehdr.e_phentsize;
    Elf64_Addr current_addr = current_offset;

    int previous_flags = 0;
    for (int segnum = 0; segnum < binary->ehdr.e_shnum; segnum++) {
        Elf64_Shdr *shdr = &binary->shdrs[segnum];
        if (shdr->sh_addralign > 0) {
            Elf64_Off align = shdr->sh_addralign;
            current_offset = (current_offset + align - 1) & ~(align - 1);
            current_addr = (current_addr + align - 1) & ~(align - 1);
        }
        // Align to 4096 page if the segment changed (detected by flag change)
        int flags = shdr->sh_flags & SHF_EXECINSTR;
        if (shdr->sh_type != SHT_NULL && flags != previous_flags) {
            current_offset = (current_offset + 4096 - 1) & ~(4096 - 1);
            current_addr = (current_addr + 4096 - 1) & ~(4096 - 1);
            previous_flags = flags;
        }
        Elf64_Off predicted_offset = shdr->sh_type == SHT_NULL ? 0 : current_offset;
        Elf64_Addr predicted_addr = is_file_only_section(binary, shdr) ? 0 : current_addr;
        if (shdr->sh_offset == (Elf64_Off)(-1) || shdr->sh_offset == predicted_offset) {
            shdr->sh_offset = predicted_offset;
        } else {
            current_offset = shdr->sh_offset;
        }
        if (shdr->sh_addr == (Elf64_Off)(-1) || shdr->sh_addr == predicted_addr) {
            shdr->sh_addr = predicted_addr;
        } else {
            current_addr = shdr->sh_addr;
        }
        if (shdr->sh_type != SHT_NOBITS) {
            current_offset += shdr->sh_size;
        }
        current_addr += shdr->sh_size;
    }
}

bool is_default_section_offset(const ElfBinary *binary, int target_segnum, Elf64_Off offset) {
    Elf64_Off current_offset = binary->ehdr.e_ehsize + binary->ehdr.e_phnum * binary->ehdr.e_phentsize;

    int previous_flags = 0;
    for (int segnum = 0; segnum < binary->ehdr.e_shnum; segnum++) {
        Elf64_Shdr *shdr = &binary->shdrs[segnum];
        if (shdr->sh_addralign > 0) {
            Elf64_Off align = shdr->sh_addralign;
            current_offset = (current_offset + align - 1) & ~(align - 1);
        }
        // Align to 4096 page if the segment changed (detected by flag change)
        int flags = shdr->sh_flags & SHF_EXECINSTR;
        if (shdr->sh_type != SHT_NULL && flags != previous_flags) {
            current_offset = (current_offset + 4096 - 1) & ~(4096 - 1);
            previous_flags = flags;
        }
        Elf64_Off predicted_offset = shdr->sh_type == SHT_NULL ? 0 : current_offset;
        if (segnum == target_segnum) {
            return predicted_offset == offset;
        }
        if (shdr->sh_type != SHT_NULL && shdr->sh_offset != (Elf64_Off)(-1)) {
            current_offset = shdr->sh_offset;
        }
        if (shdr->sh_type != SHT_NOBITS) {
            current_offset += shdr->sh_size;
        }
    }
    return false;
}

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
    calculate_section_offsets(binary);
}

bool is_default_e_phoff(const ElfBinary *binary) {
    return binary->ehdr.e_phoff == sizeof(Elf64_Ehdr);
}

bool is_default_e_phentsize(const ElfBinary *binary) {
    return binary->ehdr.e_phentsize == sizeof(Elf64_Phdr);
}

bool is_default_e_shentsize(const ElfBinary *binary) {
    return binary->ehdr.e_shentsize == sizeof(Elf64_Shdr);
}
