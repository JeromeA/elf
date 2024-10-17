#include "lisp_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static FILE *open_lisp_file(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }
    return fp;
}

/* Function to map string to e_type value */
static Elf64_Half get_e_type_value(const char *str) {
    if (strcmp(str, "ET_NONE") == 0) return ET_NONE;
    if (strcmp(str, "ET_REL") == 0) return ET_REL;
    if (strcmp(str, "ET_EXEC") == 0) return ET_EXEC;
    if (strcmp(str, "ET_DYN") == 0) return ET_DYN;
    if (strcmp(str, "ET_CORE") == 0) return ET_CORE;
    if (strncmp(str, "ET_UNKNOWN(", 11) == 0) {
        return (Elf64_Half)atoi(str + 11);
    }
    fprintf(stderr, "Unknown e_type: %s\n", str);
    exit(EXIT_FAILURE);
}

/* Function to map string to e_machine value */
static Elf64_Half get_e_machine_value(const char *str) {
    if (strcmp(str, "EM_NONE") == 0) return EM_NONE;
    if (strcmp(str, "EM_386") == 0) return EM_386;
    if (strcmp(str, "EM_X86_64") == 0) return EM_X86_64;
    // Add other architectures as needed
    if (strncmp(str, "EM_UNKNOWN(", 11) == 0) {
        return (Elf64_Half)atoi(str + 11);
    }
    fprintf(stderr, "Unknown e_machine: %s\n", str);
    exit(EXIT_FAILURE);
}

/* Parses the ELF header from the Lisp representation with constants */
static void parse_elf_header(FILE *fp, ElfBinary *binary) {
    char line[256];
    char name[64], value_str[128];

    while (fgets(line, sizeof(line), fp)) {
        // Trim leading whitespace
        char *trimmed_line = line;
        while (isspace((unsigned char)*trimmed_line)) {
            trimmed_line++;
        }

        // Check if the line is only a closing parenthesis
        if (strcmp(trimmed_line, ")\n") == 0 || strcmp(trimmed_line, ")") == 0) {
            break; // End of elf_header
        }

        if (sscanf(line, "    (%[^ ] %[^)])", name, value_str) == 2) {
            if (strcmp(name, "e_ident") == 0) {
                // Skip '0x' prefix if present
                char *ident_str = value_str;
                if (strncmp(ident_str, "0x", 2) == 0) {
                    ident_str += 2;
                }
                for (int i = 0; i < EI_NIDENT; i++) {
                    char byte_str[3] = { ident_str[i*2], ident_str[i*2+1], '\0' };
                    binary->ehdr.e_ident[i] = (unsigned char)strtol(byte_str, NULL, 16);
                }
            } else if (strcmp(name, "e_type") == 0) {
                binary->ehdr.e_type = get_e_type_value(value_str);
            } else if (strcmp(name, "e_machine") == 0) {
                binary->ehdr.e_machine = get_e_machine_value(value_str);
            } else if (strcmp(name, "e_version") == 0) {
                binary->ehdr.e_version = (Elf64_Word)atoi(value_str);
            } else if (strcmp(name, "e_entry") == 0) {
                binary->ehdr.e_entry = (Elf64_Addr)strtoul(value_str, NULL, 0);
            } else if (strcmp(name, "e_phoff") == 0) {
                binary->ehdr.e_phoff = (Elf64_Off)atol(value_str);
            } else if (strcmp(name, "e_shoff") == 0) {
                binary->ehdr.e_shoff = (Elf64_Off)atol(value_str);
            } else if (strcmp(name, "e_flags") == 0) {
                binary->ehdr.e_flags = (Elf64_Word)atoi(value_str);
            } else if (strcmp(name, "e_ehsize") == 0) {
                binary->ehdr.e_ehsize = (Elf64_Half)atoi(value_str);
            } else if (strcmp(name, "e_phentsize") == 0) {
                binary->ehdr.e_phentsize = (Elf64_Half)atoi(value_str);
            } else if (strcmp(name, "e_phnum") == 0) {
                binary->ehdr.e_phnum = (Elf64_Half)atoi(value_str);
            } else if (strcmp(name, "e_shentsize") == 0) {
                binary->ehdr.e_shentsize = (Elf64_Half)atoi(value_str);
            } else if (strcmp(name, "e_shnum") == 0) {
                binary->ehdr.e_shnum = (Elf64_Half)atoi(value_str);
            } else if (strcmp(name, "e_shstrndx") == 0) {
                binary->ehdr.e_shstrndx = (Elf64_Half)atoi(value_str);
            }
        }
    }
}

/* Function to map string to p_type value */
static Elf64_Word get_p_type_value(const char *str) {
    if (strcmp(str, "PT_NULL") == 0) return PT_NULL;
    if (strcmp(str, "PT_LOAD") == 0) return PT_LOAD;
    if (strcmp(str, "PT_DYNAMIC") == 0) return PT_DYNAMIC;
    if (strcmp(str, "PT_INTERP") == 0) return PT_INTERP;
    if (strcmp(str, "PT_NOTE") == 0) return PT_NOTE;
    if (strcmp(str, "PT_SHLIB") == 0) return PT_SHLIB;
    if (strcmp(str, "PT_PHDR") == 0) return PT_PHDR;
    if (strcmp(str, "PT_TLS") == 0) return PT_TLS;
    // Add other segment types as needed
    if (strncmp(str, "PT_UNKNOWN(", 11) == 0) {
        return (Elf64_Word)atoi(str + 11);
    }
    fprintf(stderr, "Unknown p_type: %s\n", str);
    exit(EXIT_FAILURE);
}

static Elf64_Word get_p_flags_value(const char *str) {
    Elf64_Word flags = 0;

    // Split the input string by '|'
    char temp_str[32];
    strncpy(temp_str, str, sizeof(temp_str) - 1);
    temp_str[sizeof(temp_str) - 1] = '\0';

    char *token = strtok(temp_str, "|");
    while (token != NULL) {
        if (strcmp(token, "PF_R") == 0)
            flags |= PF_R;
        else if (strcmp(token, "PF_W") == 0)
            flags |= PF_W;
        else if (strcmp(token, "PF_X") == 0)
            flags |= PF_X;
        else if (strcmp(token, "0") == 0)
            flags |= 0;
        else {
            fprintf(stderr, "Unknown p_flags value: %s\n", token);
            exit(EXIT_FAILURE);
        }
        token = strtok(NULL, "|");
    }

    return flags;
}

/* Parses the program headers from the Lisp representation with constants */
static void parse_program_headers(FILE *fp, ElfBinary *binary) {
    char line[256];
    char name[64], value_str[128];
    int phdr_count = 0;
    int phdr_capacity = 4;

    binary->phdrs = malloc(sizeof(Elf64_Phdr) * phdr_capacity);
    if (!binary->phdrs) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    memset(binary->phdrs, 0, sizeof(Elf64_Phdr) * phdr_capacity);

    while (fgets(line, sizeof(line), fp)) {
        // Trim leading whitespace
        char *trimmed_line = line;
        while (isspace((unsigned char)*trimmed_line)) {
            trimmed_line++;
        }

        if (strncmp(trimmed_line, "(program_header", 15) == 0) {
            if (phdr_count == phdr_capacity) {
                phdr_capacity *= 2;
                binary->phdrs = realloc(binary->phdrs, sizeof(Elf64_Phdr) * phdr_capacity);
                if (!binary->phdrs) {
                    perror("realloc");
                    exit(EXIT_FAILURE);
                }
            }
            Elf64_Phdr *current_phdr = &binary->phdrs[phdr_count++];
            memset(current_phdr, 0, sizeof(Elf64_Phdr));

            while (fgets(line, sizeof(line), fp)) {
                // Trim leading whitespace
                char *inner_trimmed_line = line;
                while (isspace((unsigned char)*inner_trimmed_line)) {
                    inner_trimmed_line++;
                }

                // Check if the line is only a closing parenthesis
                if (strcmp(inner_trimmed_line, ")\n") == 0 || strcmp(inner_trimmed_line, ")") == 0) {
                    break; // End of program_header
                }

                if (sscanf(line, "      (p_%[^ ] %[^)])", name, value_str) == 2) {
                    if (strcmp(name, "type") == 0) {
                        current_phdr->p_type = get_p_type_value(value_str);
                    } else if (strcmp(name, "flags") == 0) {
                        current_phdr->p_flags = get_p_flags_value(value_str);
                    } else if (strcmp(name, "offset") == 0) {
                        current_phdr->p_offset = (Elf64_Off)atol(value_str);
                    } else if (strcmp(name, "vaddr") == 0) {
                        current_phdr->p_vaddr = (Elf64_Addr)strtoul(value_str, NULL, 0);
                    } else if (strcmp(name, "paddr") == 0) {
                        current_phdr->p_paddr = (Elf64_Addr)strtoul(value_str, NULL, 0);
                    } else if (strcmp(name, "filesz") == 0) {
                        current_phdr->p_filesz = (Elf64_Xword)atol(value_str);
                    } else if (strcmp(name, "memsz") == 0) {
                        current_phdr->p_memsz = (Elf64_Xword)atol(value_str);
                    } else if (strcmp(name, "align") == 0) {
                        current_phdr->p_align = (Elf64_Xword)atol(value_str);
                    }
                }
            }
        } else if (strcmp(trimmed_line, ")\n") == 0 || strcmp(trimmed_line, ")") == 0) {
            break; // End of program_headers
        }
    }

    binary->ehdr.e_phnum = phdr_count;
}

static void parse_lisp_representation(FILE *fp, ElfBinary *binary) {
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "(elf_header")) {
            parse_elf_header(fp, binary);
        } else if (strstr(line, "(program_headers")) {
            parse_program_headers(fp, binary);
        }
    }
}

void parse_lisp_file(const char *filename, ElfBinary *binary) {
    FILE *fp = open_lisp_file(filename);
    parse_lisp_representation(fp, binary);
    fclose(fp);
}

