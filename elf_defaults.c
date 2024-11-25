#include "elf_defaults.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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

static Elf64_Off
get_default_section_offset(const ElfBinary *binary, int target_segnum) {
    Elf64_Off current_offset = binary->ehdr.e_ehsize + binary->ehdr.e_phnum * binary->ehdr.e_phentsize;
    int previous_flags = 0;

    for (int segnum = 0; segnum <= target_segnum && segnum < binary->ehdr.e_shnum; segnum++) {
        Elf64_Shdr *shdr = &binary->shdrs[segnum];

        // Align current offset
        if (shdr->sh_addralign > 0) {
            Elf64_Off align = shdr->sh_addralign;
            current_offset = (current_offset + align - 1) & ~(align - 1);
        }

        // Page alignment if segment flags changed
        int flags = shdr->sh_flags & SHF_EXECINSTR;
        if (shdr->sh_type != SHT_NULL && flags != previous_flags) {
            current_offset = (current_offset + 4096 - 1) & ~(4096 - 1);
            previous_flags = flags;
        }

        Elf64_Off predicted_offset = shdr->sh_type == SHT_NULL ? 0 : current_offset;

        // Return predicted offset for the target segment
        if (segnum == target_segnum) {
            return predicted_offset;
        }

        // Update current offset if sh_offset is set to a custom value
        if (shdr->sh_offset != (Elf64_Off)(-1) && shdr->sh_offset != predicted_offset) {
            current_offset = shdr->sh_offset;
        }

        // Increase current offset by section size if not NOBITS
        if (shdr->sh_type != SHT_NOBITS) {
            current_offset += shdr->sh_size;
        }
    }

    // Default to 0 if target segment not found (shouldn't happen)
    return 0;
}

static Elf64_Addr
get_default_section_address(const ElfBinary *binary, int target_segnum) {
    Elf64_Addr current_addr = binary->ehdr.e_ehsize + binary->ehdr.e_phnum * binary->ehdr.e_phentsize;
    int previous_flags = 0;

    for (int segnum = 0; segnum <= target_segnum && segnum < binary->ehdr.e_shnum; segnum++) {
        Elf64_Shdr *shdr = &binary->shdrs[segnum];

        // Align current offset and address
        if (shdr->sh_addralign > 0) {
            Elf64_Off align = shdr->sh_addralign;
            current_addr = (current_addr + align - 1) & ~(align - 1);
        }

        // Page alignment if segment flags changed
        int flags = shdr->sh_flags & SHF_EXECINSTR;
        if (shdr->sh_type != SHT_NULL && flags != previous_flags) {
            current_addr = (current_addr + 4096 - 1) & ~(4096 - 1);
            previous_flags = flags;
        }

        Elf64_Addr predicted_addr = is_file_only_section(binary, shdr) ? 0 : current_addr;

        // Return predicted address for the target segment
        if (segnum == target_segnum) {
            return predicted_addr;
        }

        // Update current address if sh_addr is set to a custom value
        if (shdr->sh_addr != (Elf64_Off)(-1) && shdr->sh_addr != predicted_addr) {
            current_addr = shdr->sh_addr;
        }

        // Increase current address by section size
        current_addr += shdr->sh_size;
    }

    // Default to 0 if target segment not found (shouldn't happen)
    return 0;
}

Elf64_Off
get_default_e_shoff(const Elf64_Shdr *shdrs, size_t shnum) {
    if (shdrs == NULL || shnum == 0) {
        // No sections, return 0 as no section header table is needed
        return 0;
    }

    Elf64_Off last_section_end = 0;

    // Find the end offset of the last section
    for (size_t i = 0; i < shnum; i++) {
        Elf64_Off section_end = shdrs[i].sh_offset + shdrs[i].sh_size;
        if (section_end > last_section_end) {
            last_section_end = section_end;
        }
    }

    // Align the resulting offset to an 8-byte boundary
    last_section_end = (last_section_end + 0x7) & ~0x7; // Align to 8 bytes

    return last_section_end;
}

Elf64_Half
get_default_e_shstrndx(const ElfBinary *binary) {
    for (size_t i = 0; i < binary->ehdr.e_shnum; ++i) {
        if (binary->section_data[i] != NULL && binary->section_data[i][0] == '\0' && binary->section_data[i][1] == '.') {
            return i;
        }
    }
    return 0;
}

static void fill_section_offsets(const ElfBinary *binary) {
    for (int segnum = 0; segnum < binary->ehdr.e_shnum; segnum++) {
        Elf64_Shdr *shdr = &binary->shdrs[segnum];

        Elf64_Off default_offset = get_default_section_offset(binary, segnum);
        Elf64_Addr default_addr = get_default_section_address(binary, segnum);

        // Set default offset if not explicitly specified
        if (shdr->sh_offset == (Elf64_Off)(-1)) {
            shdr->sh_offset = default_offset;
        }

        // Set default address if not explicitly specified
        if (shdr->sh_addr == (Elf64_Off)(-1)) {
            shdr->sh_addr = default_addr;
        }
    }
}

int fill_phdr_defaults(ElfBinary *binary, Elf64_Phdr *phdr, Elf64_Half phnum) {
    if (phdr->p_type == PT_PHDR) {
        if (phdr->p_offset == (Elf64_Off)(-1)) phdr->p_offset = 64;
        if (phdr->p_vaddr == (Elf64_Addr)(-1)) phdr->p_vaddr = 64;
        if (phdr->p_paddr == (Elf64_Addr)(-1)) phdr->p_paddr = 64;
        if (phdr->p_filesz == (Elf64_Xword)(-1)) phdr->p_filesz = phnum * sizeof(Elf64_Phdr);
        if (phdr->p_memsz == (Elf64_Xword)(-1)) phdr->p_memsz = phnum * sizeof(Elf64_Phdr);
    } else if (phdr->p_type == PT_INTERP) {
        // Find the ".interp" section
        for (int i = 0; i < binary->ehdr.e_shnum; i++) {
            Elf64_Shdr *shdr = &binary->shdrs[i];
            if (strcmp(get_section_name(binary, shdr), ".interp") == 0) {
                if (phdr->p_offset == (Elf64_Off)(-1)) phdr->p_offset = shdr->sh_offset;
                if (phdr->p_vaddr == (Elf64_Addr)(-1)) phdr->p_vaddr = shdr->sh_addr;
                if (phdr->p_paddr == (Elf64_Addr)(-1)) phdr->p_paddr = shdr->sh_addr;
                if (phdr->p_filesz == (Elf64_Xword)(-1)) phdr->p_filesz = shdr->sh_size;
                if (phdr->p_memsz == (Elf64_Xword)(-1)) phdr->p_memsz = shdr->sh_size;
                break;
            }
        }
    } else {
        if (phdr->p_offset == (Elf64_Off)(-1) || phdr->p_vaddr == (Elf64_Addr)(-1) ||
            phdr->p_paddr == (Elf64_Addr)(-1) || phdr->p_filesz == (Elf64_Xword)(-1) ||
            phdr->p_memsz == (Elf64_Xword)(-1)) {
            return -1; // Indicate error
        }
    }
    return 0; // Success
}

void compute_defaults(ElfBinary *binary) {
    for (int i = 0; i < binary->ehdr.e_phnum; i++) {
        Elf64_Phdr *phdr = &binary->phdrs[i];
        if (fill_phdr_defaults(binary, phdr, binary->ehdr.e_phnum) != 0) {
            fprintf(stderr, "Error: Missing fields in program header of type %d\n", phdr->p_type);
            exit(EXIT_FAILURE);
        }
    }
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
    if (binary->ehdr.e_shstrndx == 0) {
        binary->ehdr.e_shstrndx = get_default_e_shstrndx(binary);
    }
    // shstrndx must be set before calling fill_section_offsets, as it is used to identify the sections.
    fill_section_offsets(binary);
    // The sections offsets must be filled before computing the default e_shoff.
    if (binary->ehdr.e_shoff == 0 && binary->ehdr.e_shnum > 0) {
        binary->ehdr.e_shoff = get_default_e_shoff(binary->shdrs, binary->ehdr.e_shnum);
    }
}

bool is_default_section_offset(const ElfBinary *binary, int target_segnum, Elf64_Off offset) {
    Elf64_Off default_offset = get_default_section_offset(binary, target_segnum);
    return offset == default_offset;
}

bool is_default_section_addr(const ElfBinary *binary, int target_segnum, Elf64_Addr addr) {
    Elf64_Addr default_addr = get_default_section_address(binary, target_segnum);
    return addr == default_addr;
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

bool is_default_e_shoff(const ElfBinary *binary) {
    return binary->ehdr.e_shoff == get_default_e_shoff(binary->shdrs, binary->ehdr.e_shnum);
}

bool is_default_e_shstrndx(const ElfBinary *binary) {
    return binary->ehdr.e_shstrndx == get_default_e_shstrndx(binary);
}

