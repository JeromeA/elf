#include "decode.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

/* Function prototypes for internal use */
static int open_file_for_reading(const char *filename);
static void *map_file_to_memory(int fd, size_t *size);
static void verify_elf_magic(const Elf64_Ehdr *ehdr);
static Elf64_Phdr *read_program_headers(const Elf64_Ehdr *ehdr, const void *map);
static void output_lisp_representation(const ElfBinary *binary);
static void output_elf_header_lisp(const Elf64_Ehdr *ehdr);
static void output_program_headers_lisp(const Elf64_Ehdr *ehdr, const Elf64_Phdr *phdrs);

/* Main function to decode an ELF file */
void decode_elf(const char *filename) {
    int fd = open_file_for_reading(filename);
    size_t filesize;
    void *map = map_file_to_memory(fd, &filesize);
    close(fd);

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)map;
    verify_elf_magic(ehdr);

    ElfBinary binary;
    memcpy(&binary.ehdr, ehdr, sizeof(Elf64_Ehdr));
    binary.phdrs = read_program_headers(ehdr, map);

    output_lisp_representation(&binary);

    free_elf_binary(&binary);
    munmap(map, filesize);
}

/* Opens a file for reading */
static int open_file_for_reading(const char *filename) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    return fd;
}

/* Maps the file into memory */
static void *map_file_to_memory(int fd, size_t *size) {
    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        exit(EXIT_FAILURE);
    }
    *size = st.st_size;
    void *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        perror("mmap");
        close(fd);
        exit(EXIT_FAILURE);
    }
    return map;
}

/* Verifies the ELF magic number */
static void verify_elf_magic(const Elf64_Ehdr *ehdr) {
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "File is not an ELF binary.\n");
        exit(EXIT_FAILURE);
    }
}

/* Reads the program headers from the mapped file */
static Elf64_Phdr *read_program_headers(const Elf64_Ehdr *ehdr, const void *map) {
    Elf64_Phdr *phdrs = malloc(sizeof(Elf64_Phdr) * ehdr->e_phnum);
    if (!phdrs) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    memcpy(phdrs, (const char *)map + ehdr->e_phoff, sizeof(Elf64_Phdr) * ehdr->e_phnum);
    return phdrs;
}

/* Outputs the entire ELF binary in Lisp format */
static void output_lisp_representation(const ElfBinary *binary) {
    printf("(elf_binary\n");
    output_elf_header_lisp(&binary->ehdr);
    output_program_headers_lisp(&binary->ehdr, binary->phdrs);
    printf(")\n");
}

/* Function to map e_type to its string representation */
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

/* Function to map e_machine to its string representation */
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

/* Outputs the ELF header in Lisp format with constants */
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

/* Function to map p_type to its string representation */
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
        // Add other segment types as needed
        default: {
            static char unknown_str[32];
            snprintf(unknown_str, sizeof(unknown_str), "PT_UNKNOWN(%u)", p_type);
            return unknown_str;
        }
    }
}

/* Outputs the program headers in Lisp format with constants */
static void output_program_headers_lisp(const Elf64_Ehdr *ehdr, const Elf64_Phdr *phdrs) {
    printf("  (program_headers\n");
    for (int i = 0; i < ehdr->e_phnum; i++) {
        const Elf64_Phdr *phdr = &phdrs[i];
        printf("    (program_header\n");
        printf("      (p_type %s)\n", get_p_type_string(phdr->p_type));
        printf("      (p_flags 0x%x)\n", phdr->p_flags);
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
