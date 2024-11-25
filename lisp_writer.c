#include "lisp_writer.h"
#include "elf_defaults.h"
#include "elf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

static const char *get_p_flags_string(Elf64_Word p_flags) {
    static char flags_str[32];
    flags_str[0] = '\0';

    if (p_flags & PF_R) strcat(flags_str, "PF_R|");
    if (p_flags & PF_W) strcat(flags_str, "PF_W|");
    if (p_flags & PF_X) strcat(flags_str, "PF_X|");

    // Remove trailing '|'
    size_t len = strlen(flags_str);
    if (len > 0 && flags_str[len - 1] == '|') {
        flags_str[len - 1] = '\0';
    }

    // If no flags are set, indicate none
    if (flags_str[0] == '\0') {
        strcpy(flags_str, "0");
    }

    return flags_str;
}

static const char *get_p_type_string(Elf64_Word p_type) {
    switch (p_type) {
        case PT_NULL: return "PT_NULL";
        case PT_LOAD: return "PT_LOAD";
        case PT_DYNAMIC: return "PT_DYNAMIC";
        case PT_INTERP: return "PT_INTERP";
        case PT_NOTE: return "PT_NOTE";
        case PT_SHLIB: return "PT_SHLIB";
        case PT_PHDR: return "PT_PHDR";
        case PT_TLS: return "PT_TLS";
        // GNU-specific segment types
        case PT_GNU_EH_FRAME: return "PT_GNU_EH_FRAME";
        case PT_GNU_STACK: return "PT_GNU_STACK";
        case PT_GNU_RELRO: return "PT_GNU_RELRO";
        case PT_GNU_PROPERTY: return "PT_GNU_PROPERTY";
        case PT_GNU_SFRAME: return "PT_GNU_SFRAME";
        // Sun-specific segment types
        case PT_SUNWBSS: return "PT_SUNWBSS";
        case PT_SUNWSTACK: return "PT_SUNWSTACK";
        default: {
            static char unknown_str[32];
            snprintf(unknown_str, sizeof(unknown_str), "PT_UNKNOWN(%u)", p_type);
            return unknown_str;
        }
    }
}

static void output_program_headers_lisp(size_t phnum, const Elf64_Phdr *phdrs, FILE *fp) {
    fprintf(fp, "  (program_headers\n");
    for (size_t i = 0; i < phnum; i++) {
        const Elf64_Phdr *phdr = &phdrs[i];
        Elf64_Phdr default_phdr = *phdr;
        default_phdr.p_offset = (Elf64_Off)(-1);
        default_phdr.p_vaddr = (Elf64_Addr)(-1);
        default_phdr.p_paddr = (Elf64_Addr)(-1);
        default_phdr.p_filesz = (Elf64_Xword)(-1);
        default_phdr.p_memsz = (Elf64_Xword)(-1);
        fill_phdr_defaults(&default_phdr, phnum);
        fprintf(fp, "    (program_header\n");
        fprintf(fp, "      (p_type %s)\n", get_p_type_string(phdr->p_type));
        fprintf(fp, "      (p_flags %s)\n", get_p_flags_string(phdr->p_flags));
        fprintf(fp, "      %s(p_offset %lu)\n", phdr->p_offset == default_phdr.p_offset ? ";" : "", phdr->p_offset);
        fprintf(fp, "      %s(p_vaddr 0x%lx)\n", phdr->p_vaddr == default_phdr.p_vaddr ? ";" : "", phdr->p_vaddr);
        fprintf(fp, "      %s(p_paddr 0x%lx)\n", phdr->p_paddr == default_phdr.p_paddr ? ";" : "", phdr->p_paddr);
        fprintf(fp, "      %s(p_filesz %lu)\n", phdr->p_filesz == default_phdr.p_filesz ? ";" : "", phdr->p_filesz);
        fprintf(fp, "      %s(p_memsz %lu)\n", phdr->p_memsz == default_phdr.p_memsz ? ";" : "", phdr->p_memsz);
        fprintf(fp, "      (p_align %lu)\n", phdr->p_align);
        fprintf(fp, "    )\n");
    }
    fprintf(fp, "  )\n");
}

static const char *get_e_type_string(Elf64_Half e_type) {
    switch (e_type) {
        case ET_NONE: return "ET_NONE";
        case ET_REL: return "ET_REL";
        case ET_EXEC: return "ET_EXEC";
        case ET_DYN: return "ET_DYN";
        case ET_CORE: return "ET_CORE";
        default: {
            static char unknown_str[32];
            snprintf(unknown_str, sizeof(unknown_str), "ET_UNKNOWN(%u)", e_type);
            return unknown_str;
        }
    }
}

static const char *get_e_machine_string(Elf64_Half e_machine) {
    switch (e_machine) {
        case EM_NONE: return "EM_NONE";
        case EM_386: return "EM_386";
        case EM_X86_64: return "EM_X86_64";
        // Add other architectures as needed
        default: {
            static char unknown_str[32];
            snprintf(unknown_str, sizeof(unknown_str), "EM_UNKNOWN(%u)", e_machine);
            return unknown_str;
        }
    }
}

static void output_elf_header_lisp(const ElfBinary *binary, FILE *fp) {
    const Elf64_Ehdr *ehdr = &binary->ehdr;
    fprintf(fp, "  (elf_header\n");
    fprintf(fp, "    (e_ident 0x");
    for (int i = 0; i < EI_NIDENT; i++) {
        fprintf(fp, "%02x", ehdr->e_ident[i]);
    }
    fprintf(fp, ")\n");
    fprintf(fp, "    (e_type %s)\n", get_e_type_string(ehdr->e_type));
    fprintf(fp, "    (e_machine %s)\n", get_e_machine_string(ehdr->e_machine));
    fprintf(fp, "    (e_version %u)\n", ehdr->e_version);
    fprintf(fp, "    (e_entry 0x%lx)\n", ehdr->e_entry);
    fprintf(fp, "    %s(e_phoff %lu)\n", is_default_e_phoff(binary) ? ";" : "", ehdr->e_phoff);
    fprintf(fp, "    %s(e_shoff %lu)\n", is_default_e_shoff(binary) ? ";" : "", ehdr->e_shoff);
    fprintf(fp, "    (e_flags %u)\n", ehdr->e_flags);
    fprintf(fp, "    ;(e_ehsize %u)\n", ehdr->e_ehsize);
    fprintf(fp, "    %s(e_phentsize %u)\n", is_default_e_phentsize(binary) ? ";" : "", ehdr->e_phentsize);
    fprintf(fp, "    ;(e_phnum %u)\n", ehdr->e_phnum);
    fprintf(fp, "    %s(e_shentsize %u)\n", is_default_e_shentsize(binary) ? ";" : "", ehdr->e_shentsize);
    fprintf(fp, "    ;(e_shnum %u)\n", ehdr->e_shnum);
    fprintf(fp, "    %s(e_shstrndx %u)\n", is_default_e_shstrndx(binary) ? ";" : "", ehdr->e_shstrndx);
    fprintf(fp, "  )\n");
}

static const char *get_sh_type_string(Elf64_Word sh_type) {
    switch (sh_type) {
        case SHT_NULL:            return "SHT_NULL";
        case SHT_PROGBITS:        return "SHT_PROGBITS";
        case SHT_SYMTAB:          return "SHT_SYMTAB";
        case SHT_STRTAB:          return "SHT_STRTAB";
        case SHT_RELA:            return "SHT_RELA";
        case SHT_HASH:            return "SHT_HASH";
        case SHT_DYNAMIC:         return "SHT_DYNAMIC";
        case SHT_NOTE:            return "SHT_NOTE";
        case SHT_NOBITS:          return "SHT_NOBITS";
        case SHT_REL:             return "SHT_REL";
        case SHT_SHLIB:           return "SHT_SHLIB";
        case SHT_DYNSYM:          return "SHT_DYNSYM";
        case SHT_INIT_ARRAY:      return "SHT_INIT_ARRAY";
        case SHT_FINI_ARRAY:      return "SHT_FINI_ARRAY";
        case SHT_PREINIT_ARRAY:   return "SHT_PREINIT_ARRAY";
        case SHT_GROUP:           return "SHT_GROUP";
        case SHT_SYMTAB_SHNDX:    return "SHT_SYMTAB_SHNDX";
        case SHT_RELR:            return "SHT_RELR";
        case SHT_NUM:             return "SHT_NUM";
        case SHT_LOOS:            return "SHT_LOOS";
        case SHT_GNU_ATTRIBUTES:  return "SHT_GNU_ATTRIBUTES";
        case SHT_GNU_HASH:        return "SHT_GNU_HASH";
        case SHT_GNU_LIBLIST:     return "SHT_GNU_LIBLIST";
        case SHT_CHECKSUM:        return "SHT_CHECKSUM";
        case SHT_SUNW_move:       return "SHT_SUNW_move";
        case SHT_SUNW_COMDAT:     return "SHT_SUNW_COMDAT";
        case SHT_SUNW_syminfo:    return "SHT_SUNW_syminfo";
        case SHT_GNU_verdef:      return "SHT_GNU_verdef";
        case SHT_GNU_verneed:     return "SHT_GNU_verneed";
        case SHT_GNU_versym:      return "SHT_GNU_versym";
        default: {
            static char unknown_str[32];
            snprintf(unknown_str, sizeof(unknown_str), "SHT_UNKNOWN(0x%x)", sh_type);
            return unknown_str;
        }
    }
}

static const char *get_sh_flags_string(Elf64_Xword sh_flags) {
    static char flags_str[64];
    flags_str[0] = '\0';

    if (sh_flags & SHF_WRITE) { strcat(flags_str, "SHF_WRITE | "); }
    if (sh_flags & SHF_ALLOC) { strcat(flags_str, "SHF_ALLOC | "); }
    if (sh_flags & SHF_EXECINSTR) { strcat(flags_str, "SHF_EXECINSTR | "); }
    if (sh_flags & SHF_MERGE) { strcat(flags_str, "SHF_MERGE | "); }
    if (sh_flags & SHF_STRINGS) { strcat(flags_str, "SHF_STRINGS | "); }
    if (sh_flags & SHF_INFO_LINK) { strcat(flags_str, "SHF_INFO_LINK | "); }
    if (sh_flags & SHF_LINK_ORDER) { strcat(flags_str, "SHF_LINK_ORDER | "); }
    if (sh_flags & SHF_OS_NONCONFORMING) { strcat(flags_str, "SHF_OS_NONCONFORMING | "); }
    if (sh_flags & SHF_GROUP) { strcat(flags_str, "SHF_GROUP | "); }
    if (sh_flags & SHF_TLS) { strcat(flags_str, "SHF_TLS | "); }
    if (sh_flags & SHF_COMPRESSED) { strcat(flags_str, "SHF_COMPRESSED | "); }
    if (sh_flags & SHF_GNU_RETAIN) { strcat(flags_str, "SHF_GNU_RETAIN | "); }

    // Remove trailing ' | '
    size_t len = strlen(flags_str);
    if (len > 0) {
        flags_str[len - 3] = '\0';
    } else {
        strcpy(flags_str, "0");
    }

    return flags_str;
}

static bool is_string(const unsigned char *data, size_t size) {
    if (size == 0) return false;
    for (size_t i = 0; i < size - 1; i++) {
        if (data[i] < 0x20 || data[i] > 0x7F) {
            return false;
        }
    }
    return data[size - 1] == 0x00;
}

static bool is_string_table(const unsigned char *data, size_t size) {
    if (size < 1 || data[0] != 0x00) return false;
    size_t i = 1;
    while (i < size) {
        // Each string must consist of printable ASCII characters
        while (i < size && data[i] != 0x00) {
            if (data[i] < 0x20 || data[i] > 0x7F) {
                return false;
            }
            i++;
        }
        if (i >= size) return false;
        i++; // Move past the null terminator
    }
    return true;
}

static void output_notes_lisp(const Elf64_Shdr *shdr, const unsigned char *data, FILE *fp) {
    size_t pos = 0;
    while (pos < shdr->sh_size) {
        // Ensure there's enough data for Elf64_Nhdr
        if (pos + sizeof(Elf64_Nhdr) > shdr->sh_size) {
            fprintf(stderr, "Error: Incomplete note header\n");
            exit(EXIT_FAILURE);
        }

        Elf64_Nhdr nhdr;
        memcpy(&nhdr, &data[pos], sizeof(Elf64_Nhdr));
        pos += sizeof(Elf64_Nhdr);

        // Read name
        if (pos + nhdr.n_namesz > shdr->sh_size) {
            fprintf(stderr, "Error: Incomplete note name\n");
            exit(EXIT_FAILURE);
        }
        char *name = malloc(nhdr.n_namesz);
        if (!name) {
            perror("malloc");
            exit(EXIT_FAILURE);
        }
        memcpy(name, &data[pos], nhdr.n_namesz);
        // Ensure null-termination
        if (name[nhdr.n_namesz - 1] != '\0') {
            name[nhdr.n_namesz - 1] = '\0';
        }
        pos += (nhdr.n_namesz + 3) & ~3; // Align to 4 bytes

        // Read descriptor
        if (pos + nhdr.n_descsz > shdr->sh_size) {
            fprintf(stderr, "Error: Incomplete note descriptor\n");
            free(name);
            exit(EXIT_FAILURE);
        }
        unsigned char *descriptor = malloc(nhdr.n_descsz);
        if (!descriptor) {
            perror("malloc");
            free(name);
            exit(EXIT_FAILURE);
        }
        memcpy(descriptor, &data[pos], nhdr.n_descsz);
        pos += (nhdr.n_descsz + 3) & ~3; // Align to 4 bytes

        // Output the note
        fprintf(fp, "          (note\n");
        fprintf(fp, "            (name \"%s\")\n", name);
        fprintf(fp, "            (type %u)\n", nhdr.n_type);
        fprintf(fp, "            (descriptor x");
        for (size_t i = 0; i < nhdr.n_descsz; i++) {
            fprintf(fp, "%02X", descriptor[i]);
        }
        fprintf(fp, ")\n");
        fprintf(fp, "          )\n");

        free(name);
        free(descriptor);
    }
}

static void output_symbols_lisp(const ElfBinary *binary, const Elf64_Shdr *shdr, const unsigned char *data, FILE *fp) {
    size_t entry_count = shdr->sh_size / shdr->sh_entsize;
    const Elf64_Sym *symtab = (const Elf64_Sym *)data;

    Elf64_Word strtab_index = shdr->sh_link;
    const unsigned char *strtab = binary->section_data[strtab_index];

    for (size_t i = 0; i < entry_count; i++) {
        const Elf64_Sym *sym = &symtab[i];
        const char *name = (const char *)&strtab[sym->st_name];
        fprintf(fp, "        (symbol\n");
        fprintf(fp, "          (st_name %u)\n", sym->st_name);
        fprintf(fp, "          (st_name_str \"%s\")\n", name);
        fprintf(fp, "          (st_info %u)\n", sym->st_info);
        fprintf(fp, "          (st_other %u)\n", sym->st_other);
        fprintf(fp, "          (st_shndx %u)\n", sym->st_shndx);
        fprintf(fp, "          (st_value 0x%lx)\n", sym->st_value);
        fprintf(fp, "          (st_size %lu)\n", sym->st_size);
        fprintf(fp, "        )\n");
    }
}

static void output_relocations_lisp(const Elf64_Shdr *shdr, const unsigned char *data, bool is_rela, FILE *fp) {
    size_t entry_count = shdr->sh_size / shdr->sh_entsize;
    for (size_t i = 0; i < entry_count; i++) {
        if (is_rela) {
            const Elf64_Rela *rela = (const Elf64_Rela *)&data[i * sizeof(Elf64_Rela)];
            Elf64_Xword symbol_index = ELF64_R_SYM(rela->r_info);
            Elf64_Word relocation_type = ELF64_R_TYPE(rela->r_info);
            fprintf(fp, "        (relocation\n");
            fprintf(fp, "          (offset 0x%lx)\n", rela->r_offset);
            fprintf(fp, "          (symbol_index %lu)\n", symbol_index);
            fprintf(fp, "          (relocation_type %u)\n", relocation_type);
            fprintf(fp, "          (addend %ld)\n", rela->r_addend);
            fprintf(fp, "        )\n");
        } else {
            const Elf64_Rel *rel = (const Elf64_Rel *)&data[i * sizeof(Elf64_Rel)];
            Elf64_Xword symbol_index = ELF64_R_SYM(rel->r_info);
            Elf64_Word relocation_type = ELF64_R_TYPE(rel->r_info);
            fprintf(fp, "        (relocation\n");
            fprintf(fp, "          (offset 0x%lx)\n", rel->r_offset);
            fprintf(fp, "          (symbol_index %lu)\n", symbol_index);
            fprintf(fp, "          (relocation_type %u)\n", relocation_type);
            fprintf(fp, "        )\n");
        }
    }
}

static void output_data(const Elf64_Shdr *shdr, const unsigned char *data, const ElfBinary *binary, FILE *fp) {
    size_t size = shdr->sh_size;
    fprintf(fp, "      (data\n");
    if (shdr->sh_type == SHT_NOTE) {
        output_notes_lisp(shdr, data, fp);
    } else if (shdr->sh_type == SHT_SYMTAB) {
        output_symbols_lisp(binary, shdr, data, fp);
    } else if (shdr->sh_type == SHT_REL || shdr->sh_type == SHT_RELA) {
        output_relocations_lisp(shdr, data, shdr->sh_type == SHT_RELA, fp);
    } else if (is_string_table(data, size)) {
        size_t pos = 0;
        while (pos < size) {
            fprintf(fp, "        (string \"%s\")\n", data + pos);
            while (pos < size && data[pos]) pos++;
            pos++;
        }
    } else if (is_string(data, size)) {
        fprintf(fp, "        (string \"%s\")\n", data);
    } else {
        fprintf(fp, "        (binary x");
        for (size_t i = 0; i < size; i++) {
            fprintf(fp, "%02X", data[i]);
        }
        fprintf(fp, ")\n");
    }
    fprintf(fp, "      )\n");
}

static bool is_sh_size_implicit(const Elf64_Shdr *shdr, unsigned char *section_data) {
    if (section_data) return true;
    return shdr->sh_size == 0;
}

static void output_section_headers_lisp(size_t shnum, const Elf64_Shdr *shdrs, unsigned char **section_data, const ElfBinary *binary, FILE *fp) {
    fprintf(fp, "  (section_headers\n");
    for (size_t i = 0; i < shnum; i++) {
        const Elf64_Shdr *shdr = &shdrs[i];
        const char *section_name = get_section_name(binary, shdr);
        fprintf(fp, "    (section_header\n");
        fprintf(fp, "      (sh_name %u)\n", shdr->sh_name);
        fprintf(fp, "      (sh_name_str \"%s\")\n", section_name);
        fprintf(fp, "      (sh_type %s)\n", get_sh_type_string(shdr->sh_type));
        fprintf(fp, "      (sh_flags %s)\n", get_sh_flags_string(shdr->sh_flags));
        fprintf(fp, "      %s(sh_addr 0x%lx)\n", is_default_section_addr(binary, i, shdr->sh_addr) ? ";" : "", shdr->sh_addr);
        fprintf(fp, "      %s(sh_offset %lu)\n", is_default_section_offset(binary, i, shdr->sh_offset) ? ";" : "", shdr->sh_offset);
        fprintf(fp, "      %s(sh_size %lu)\n", is_sh_size_implicit(shdr, section_data[i]) ? ";" : "", shdr->sh_size);
        fprintf(fp, "      (sh_link %u)\n", shdr->sh_link);
        fprintf(fp, "      (sh_info %u)\n", shdr->sh_info);
        fprintf(fp, "      (sh_addralign %lu)\n", shdr->sh_addralign);
        fprintf(fp, "      (sh_entsize %lu)\n", shdr->sh_entsize);
        
        if (shdr->sh_type != SHT_NOBITS && shdr->sh_size > 0 && section_data[i]) {
          output_data(shdr, section_data[i], binary, fp);
        }
        fprintf(fp, "    )\n");
    }
    fprintf(fp, "  )\n");
}

void output_lisp_representation(const ElfBinary *binary, const char *output_filename) {
    FILE *fp = fopen(output_filename, "w");
    if (!fp) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    fprintf(fp, "(elf_binary\n");
    output_elf_header_lisp(binary, fp);
    output_program_headers_lisp(binary->ehdr.e_phnum, binary->phdrs, fp);
    output_section_headers_lisp(binary->ehdr.e_shnum, binary->shdrs, binary->section_data, binary, fp);

    fprintf(fp, ")\n");

    fclose(fp);
}

