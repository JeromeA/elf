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

void read_elf_binary(const char *filename, ElfBinary *binary) {
    int fd = open_elf_file(filename);
    size_t filesize;
    void *map = map_elf_file(fd, &filesize);
    close(fd);

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)map;
    verify_elf_magic(ehdr);

    memcpy(&binary->ehdr, ehdr, sizeof(Elf64_Ehdr));
    binary->phdrs = read_program_headers(ehdr, map);

    munmap(map, filesize);
}

