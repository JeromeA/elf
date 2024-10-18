#include "lisp_writer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static void output_program_headers_lisp(const Elf64_Ehdr *ehdr, const Elf64_Phdr *phdrs, FILE *fp) {
    fprintf(fp, "  (program_headers\n");
    for (int i = 0; i < ehdr->e_phnum; i++) {
        const Elf64_Phdr *phdr = &phdrs[i];
        fprintf(fp, "    (program_header\n");
        fprintf(fp, "      (p_type %s)\n", get_p_type_string(phdr->p_type));
        fprintf(fp, "      (p_flags %s)\n", get_p_flags_string(phdr->p_flags));
        fprintf(fp, "      (p_offset %lu)\n", phdr->p_offset);
        fprintf(fp, "      (p_vaddr 0x%lx)\n", phdr->p_vaddr);
        fprintf(fp, "      (p_paddr 0x%lx)\n", phdr->p_paddr);
        fprintf(fp, "      (p_filesz %lu)\n", phdr->p_filesz);
        fprintf(fp, "      (p_memsz %lu)\n", phdr->p_memsz);
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

static void output_elf_header_lisp(const Elf64_Ehdr *ehdr, FILE *fp) {
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
    fprintf(fp, "    (e_phoff %lu)\n", ehdr->e_phoff);
    fprintf(fp, "    (e_shoff %lu)\n", ehdr->e_shoff);
    fprintf(fp, "    (e_flags %u)\n", ehdr->e_flags);
    fprintf(fp, "    (e_ehsize %u)\n", ehdr->e_ehsize);
    fprintf(fp, "    (e_phentsize %u)\n", ehdr->e_phentsize);
    fprintf(fp, "    (e_phnum %u)\n", ehdr->e_phnum);
    fprintf(fp, "    (e_shentsize %u)\n", ehdr->e_shentsize);
    fprintf(fp, "    (e_shnum %u)\n", ehdr->e_shnum);
    fprintf(fp, "    (e_shstrndx %u)\n", ehdr->e_shstrndx);
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

static void output_section_headers_lisp(const Elf64_Ehdr *ehdr, const Elf64_Shdr *shdrs, char **section_names, unsigned char **section_data, FILE *fp) {
    fprintf(fp, "  (section_headers\n");
    for (int i = 0; i < ehdr->e_shnum; i++) {
        const Elf64_Shdr *shdr = &shdrs[i];
        const char *section_name = section_names[i];
        fprintf(fp, "    (section_header\n");
        fprintf(fp, "      (sh_name %u)\n", shdr->sh_name);
        fprintf(fp, "      (sh_name_str \"%s\")\n", section_name); // Output section name for readability
        fprintf(fp, "      (sh_type %s)\n", get_sh_type_string(shdr->sh_type));
        fprintf(fp, "      (sh_flags %s)\n", get_sh_flags_string(shdr->sh_flags));
        fprintf(fp, "      (sh_addr 0x%lx)\n", shdr->sh_addr);
        fprintf(fp, "      (sh_offset %lu)\n", shdr->sh_offset);
        fprintf(fp, "      (sh_size %lu)\n", shdr->sh_size);
        fprintf(fp, "      (sh_link %u)\n", shdr->sh_link);
        fprintf(fp, "      (sh_info %u)\n", shdr->sh_info);
        fprintf(fp, "      (sh_addralign %lu)\n", shdr->sh_addralign);
        fprintf(fp, "      (sh_entsize %lu)\n", shdr->sh_entsize);
        
        // Output section data as hex dump
        if (shdr->sh_type != SHT_NOBITS && shdr->sh_size > 0 && section_data[i]) {
            fprintf(fp, "      (sh_data #hex\"");
            for (size_t j = 0; j < shdr->sh_size; j++) {
                fprintf(fp, "%02x", section_data[i][j]);
            }
            fprintf(fp, "\")\n");
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
    output_elf_header_lisp(&binary->ehdr, fp);
    output_program_headers_lisp(&binary->ehdr, binary->phdrs, fp);
    output_section_headers_lisp(&binary->ehdr, binary->shdrs, binary->section_names, binary->section_data, fp);

    fprintf(fp, ")\n");

    fclose(fp);
}

