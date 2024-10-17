#include "lisp_writer.h"
#include <stdio.h>
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

static void output_program_headers_lisp(const Elf64_Ehdr *ehdr, const Elf64_Phdr *phdrs) {
    printf("  (program_headers\n");
    for (int i = 0; i < ehdr->e_phnum; i++) {
        const Elf64_Phdr *phdr = &phdrs[i];
        printf("    (program_header\n");
        printf("      (p_type %s)\n", get_p_type_string(phdr->p_type));
        printf("      (p_flags %s)\n", get_p_flags_string(phdr->p_flags));
        printf("      (p_offset %lu)\n", phdr->p_offset);
        printf("      (p_vaddr 0x%lx)\n", phdr->p_vaddr);
        printf("      (p_paddr 0x%lx)\n", phdr->p_paddr);
        printf("      (p_filesz %lu)\n", phdr->p_filesz);
        printf("      (p_memsz %lu)\n", phdr->p_memsz);
        printf("      (p_align %lu)\n", phdr->p_align);
        printf("    )\n");
    }
    printf("  )\n");
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

static void output_elf_header_lisp(const Elf64_Ehdr *ehdr) {
    printf("  (elf_header\n");
    printf("    (e_ident 0x");
    for (int i = 0; i < EI_NIDENT; i++) {
        printf("%02x", ehdr->e_ident[i]);
    }
    printf(")\n");
    printf("    (e_type %s)\n", get_e_type_string(ehdr->e_type));
    printf("    (e_machine %s)\n", get_e_machine_string(ehdr->e_machine));
    printf("    (e_version %u)\n", ehdr->e_version);
    printf("    (e_entry 0x%lx)\n", ehdr->e_entry);
    printf("    (e_phoff %lu)\n", ehdr->e_phoff);
    printf("    (e_shoff %lu)\n", ehdr->e_shoff);
    printf("    (e_flags %u)\n", ehdr->e_flags);
    printf("    (e_ehsize %u)\n", ehdr->e_ehsize);
    printf("    (e_phentsize %u)\n", ehdr->e_phentsize);
    printf("    (e_phnum %u)\n", ehdr->e_phnum);
    printf("    (e_shentsize %u)\n", ehdr->e_shentsize);
    printf("    (e_shnum %u)\n", ehdr->e_shnum);
    printf("    (e_shstrndx %u)\n", ehdr->e_shstrndx);
    printf("  )\n");
}

void output_lisp_representation(const ElfBinary *binary) {
    printf("(elf_binary\n");
    output_elf_header_lisp(&binary->ehdr);
    output_program_headers_lisp(&binary->ehdr, binary->phdrs);
    printf(")\n");
}

