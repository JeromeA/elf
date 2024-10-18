#include "elf_reader.h"
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>

static int open_elf_file(const char *filename) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    return fd;
}

static void *map_elf_file(int fd, size_t *size) {
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

static void verify_elf_magic(const Elf64_Ehdr *ehdr) {
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "File is not an ELF binary.\n");
        exit(EXIT_FAILURE);
    }
}

static Elf64_Phdr *read_program_headers(const Elf64_Ehdr *ehdr, const void *map) {
    Elf64_Phdr *phdrs = malloc(sizeof(Elf64_Phdr) * ehdr->e_phnum);
    if (!phdrs) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    memcpy(phdrs, (const char *)map + ehdr->e_phoff, sizeof(Elf64_Phdr) * ehdr->e_phnum);
    return phdrs;
}

static Elf64_Shdr *read_section_headers(const Elf64_Ehdr *ehdr, const void *map) {
    Elf64_Shdr *shdrs = malloc(sizeof(Elf64_Shdr) * ehdr->e_shnum);
    if (!shdrs) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    memcpy(shdrs, (const char *)map + ehdr->e_shoff, sizeof(Elf64_Shdr) * ehdr->e_shnum);
    return shdrs;
}

static char *read_shstrtab(const Elf64_Ehdr *ehdr, const Elf64_Shdr *shdrs, const void *map) {
    Elf64_Shdr shstrtab_hdr = shdrs[ehdr->e_shstrndx];
    char *shstrtab = malloc(shstrtab_hdr.sh_size);
    if (!shstrtab) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    memcpy(shstrtab, (const char *)map + shstrtab_hdr.sh_offset, shstrtab_hdr.sh_size);
    return shstrtab;
}

void read_elf_binary(const char *filename, ElfBinary *binary) {
    int fd = open_elf_file(filename);
    size_t filesize;
    void *map = map_elf_file(fd, &filesize);
    close(fd);

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)map;
    verify_elf_magic(ehdr);

    memcpy(&binary->ehdr, ehdr, sizeof(Elf64_Ehdr));
    binary->phdrs = read_program_headers(ehdr, map);
    binary->shdrs = read_section_headers(ehdr, map);
    binary->shstrtab = read_shstrtab(ehdr, binary->shdrs, map);

    // Allocate arrays for section names and data
    binary->section_names = malloc(sizeof(char *) * binary->ehdr.e_shnum);
    binary->section_data = malloc(sizeof(unsigned char *) * binary->ehdr.e_shnum);
    if (!binary->section_names || !binary->section_data) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    // Read section names and data
    for (int i = 0; i < binary->ehdr.e_shnum; i++) {
        const Elf64_Shdr *shdr = &binary->shdrs[i];
        
        // Read section name
        const char *section_name = &binary->shstrtab[shdr->sh_name];
        binary->section_names[i] = strdup(section_name);
        if (!binary->section_names[i]) {
            perror("strdup");
            exit(EXIT_FAILURE);
        }

        // Read section data
        if (shdr->sh_type != SHT_NOBITS && shdr->sh_size > 0) {
            binary->section_data[i] = malloc(shdr->sh_size);
            if (!binary->section_data[i]) {
                perror("malloc");
                exit(EXIT_FAILURE);
            }
            memcpy(binary->section_data[i], (const char *)map + shdr->sh_offset, shdr->sh_size);
        } else {
            binary->section_data[i] = NULL;
        }
    }

    munmap(map, filesize);
}

