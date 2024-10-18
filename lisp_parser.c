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
    if (strcmp(str, "PT_GNU_EH_FRAME") == 0) return PT_GNU_EH_FRAME;
    if (strcmp(str, "PT_GNU_STACK") == 0) return PT_GNU_STACK;
    if (strcmp(str, "PT_GNU_RELRO") == 0) return PT_GNU_RELRO;
    if (strcmp(str, "PT_GNU_PROPERTY") == 0) return PT_GNU_PROPERTY;
    if (strcmp(str, "PT_GNU_SFRAME") == 0) return PT_GNU_SFRAME;
    if (strcmp(str, "PT_SUNWBSS") == 0) return PT_SUNWBSS;
    if (strcmp(str, "PT_SUNWSTACK") == 0) return PT_SUNWSTACK;
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

static void parse_program_header(FILE *fp, Elf64_Phdr *phdr) {
    char line[256];
    char name[64], value_str[128];

    while (fgets(line, sizeof(line), fp)) {
        char *inner_trimmed_line = line;
        while (isspace((unsigned char)*inner_trimmed_line)) {
            inner_trimmed_line++;
        }

        if (strcmp(inner_trimmed_line, ")\n") == 0 || strcmp(inner_trimmed_line, ")") == 0) {
            break;
        }

        if (sscanf(line, "      (p_%[^ ] %[^)])", name, value_str) == 2) {
            if (strcmp(name, "type") == 0) {
                phdr->p_type = get_p_type_value(value_str);
            } else if (strcmp(name, "flags") == 0) {
                phdr->p_flags = get_p_flags_value(value_str);
            } else if (strcmp(name, "offset") == 0) {
                phdr->p_offset = (Elf64_Off)atol(value_str);
            } else if (strcmp(name, "vaddr") == 0) {
                phdr->p_vaddr = (Elf64_Addr)strtoul(value_str, NULL, 0);
            } else if (strcmp(name, "paddr") == 0) {
                phdr->p_paddr = (Elf64_Addr)strtoul(value_str, NULL, 0);
            } else if (strcmp(name, "filesz") == 0) {
                phdr->p_filesz = (Elf64_Xword)atol(value_str);
            } else if (strcmp(name, "memsz") == 0) {
                phdr->p_memsz = (Elf64_Xword)atol(value_str);
            } else if (strcmp(name, "align") == 0) {
                phdr->p_align = (Elf64_Xword)atol(value_str);
            }
        }
    }
}

static void parse_program_headers(FILE *fp, ElfBinary *binary) {
    char line[256];
    int phdr_count = 0;
    int phdr_capacity = 4;

    binary->phdrs = calloc(phdr_capacity, sizeof(Elf64_Phdr));
    if (!binary->phdrs) {
        perror("calloc");
        exit(EXIT_FAILURE);
    }

    while (fgets(line, sizeof(line), fp)) {
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
            Elf64_Phdr *current_phdr = &binary->phdrs[phdr_count];
            memset(current_phdr, 0, sizeof(Elf64_Phdr));

            parse_program_header(fp, current_phdr);
            phdr_count++;
        } else if (strcmp(trimmed_line, ")\n") == 0 || strcmp(trimmed_line, ")") == 0) {
            break;
        }
    }

    binary->ehdr.e_phnum = phdr_count;
}

static Elf64_Word get_sh_type_value(const char *str) {
    if (strcmp(str, "SHT_NULL") == 0)            return SHT_NULL;
    if (strcmp(str, "SHT_PROGBITS") == 0)        return SHT_PROGBITS;
    if (strcmp(str, "SHT_SYMTAB") == 0)          return SHT_SYMTAB;
    if (strcmp(str, "SHT_STRTAB") == 0)          return SHT_STRTAB;
    if (strcmp(str, "SHT_RELA") == 0)            return SHT_RELA;
    if (strcmp(str, "SHT_HASH") == 0)            return SHT_HASH;
    if (strcmp(str, "SHT_DYNAMIC") == 0)         return SHT_DYNAMIC;
    if (strcmp(str, "SHT_NOTE") == 0)            return SHT_NOTE;
    if (strcmp(str, "SHT_NOBITS") == 0)          return SHT_NOBITS;
    if (strcmp(str, "SHT_REL") == 0)             return SHT_REL;
    if (strcmp(str, "SHT_SHLIB") == 0)           return SHT_SHLIB;
    if (strcmp(str, "SHT_DYNSYM") == 0)          return SHT_DYNSYM;
    if (strcmp(str, "SHT_INIT_ARRAY") == 0)      return SHT_INIT_ARRAY;
    if (strcmp(str, "SHT_FINI_ARRAY") == 0)      return SHT_FINI_ARRAY;
    if (strcmp(str, "SHT_PREINIT_ARRAY") == 0)   return SHT_PREINIT_ARRAY;
    if (strcmp(str, "SHT_GROUP") == 0)           return SHT_GROUP;
    if (strcmp(str, "SHT_SYMTAB_SHNDX") == 0)    return SHT_SYMTAB_SHNDX;
    if (strcmp(str, "SHT_RELR") == 0)            return SHT_RELR;
    if (strcmp(str, "SHT_NUM") == 0)             return SHT_NUM;
    if (strcmp(str, "SHT_LOOS") == 0)            return SHT_LOOS;
    if (strcmp(str, "SHT_GNU_ATTRIBUTES") == 0)  return SHT_GNU_ATTRIBUTES;
    if (strcmp(str, "SHT_GNU_HASH") == 0)        return SHT_GNU_HASH;
    if (strcmp(str, "SHT_GNU_LIBLIST") == 0)     return SHT_GNU_LIBLIST;
    if (strcmp(str, "SHT_CHECKSUM") == 0)        return SHT_CHECKSUM;
    if (strcmp(str, "SHT_SUNW_move") == 0)       return SHT_SUNW_move;
    if (strcmp(str, "SHT_SUNW_COMDAT") == 0)     return SHT_SUNW_COMDAT;
    if (strcmp(str, "SHT_SUNW_syminfo") == 0)    return SHT_SUNW_syminfo;
    if (strcmp(str, "SHT_GNU_verdef") == 0)      return SHT_GNU_verdef;
    if (strcmp(str, "SHT_GNU_verneed") == 0)     return SHT_GNU_verneed;
    if (strcmp(str, "SHT_GNU_versym") == 0)      return SHT_GNU_versym;

    // Handle unknown types
    if (strncmp(str, "SHT_UNKNOWN(", 12) == 0) {
        return (Elf64_Word)strtoul(str + 12, NULL, 0);
    }

    fprintf(stderr, "Unknown sh_type: %s\n", str);
    exit(EXIT_FAILURE);
}

static Elf64_Xword get_sh_flags_value(const char *str) {
    Elf64_Xword flags = 0;
    char *token;
    char *input_str = strdup(str);
    if (!input_str) {
        perror("strdup");
        exit(EXIT_FAILURE);
    }

    token = strtok(input_str, " |");
    while (token != NULL) {
        if (strcmp(token, "SHF_WRITE") == 0) {
            flags |= SHF_WRITE;
        } else if (strcmp(token, "SHF_ALLOC") == 0) {
            flags |= SHF_ALLOC;
        } else if (strcmp(token, "SHF_EXECINSTR") == 0) {
            flags |= SHF_EXECINSTR;
        } else if (strcmp(token, "SHF_MERGE") == 0) {
            flags |= SHF_MERGE;
        } else if (strcmp(token, "SHF_STRINGS") == 0) {
            flags |= SHF_STRINGS;
        } else if (strcmp(token, "SHF_INFO_LINK") == 0) {
            flags |= SHF_INFO_LINK;
        } else if (strcmp(token, "SHF_LINK_ORDER") == 0) {
            flags |= SHF_LINK_ORDER;
        } else if (strcmp(token, "SHF_OS_NONCONFORMING") == 0) {
            flags |= SHF_OS_NONCONFORMING;
        } else if (strcmp(token, "SHF_GROUP") == 0) {
            flags |= SHF_GROUP;
        } else if (strcmp(token, "SHF_TLS") == 0) {
            flags |= SHF_TLS;
        } else if (strcmp(token, "SHF_COMPRESSED") == 0) {
            flags |= SHF_COMPRESSED;
        } else if (strcmp(token, "SHF_GNU_RETAIN") == 0) {
            flags |= SHF_GNU_RETAIN;
        } else if (strcmp(token, "0") == 0) {
            // No flags set
        } else {
            fprintf(stderr, "Unknown sh_flag: %s\n", token);
            exit(EXIT_FAILURE);
        }

        token = strtok(NULL, " |");
    }

    free(input_str);
    return flags;
}

// Function to parse a field line and extract the field name and value
static void parse_field(const char *line, char **out_name, char **out_value) {
    const char *start = line;

    // Skip leading whitespace
    while (isspace((unsigned char)*start)) {
        start++;
    }

    // Expecting '('
    if (*start != '(') {
        fprintf(stderr, "Error: Expected '(', got '%c'\n", *start);
        exit(EXIT_FAILURE);
    }
    start++;

    // Extract field name
    const char *name_start = start;
    while (*start && !isspace((unsigned char)*start)) {
        start++;
    }
    size_t name_len = start - name_start;
    char *name = malloc(name_len + 1);
    if (!name) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    strncpy(name, name_start, name_len);
    name[name_len] = '\0';

    // Skip whitespace before value
    while (isspace((unsigned char)*start)) {
        start++;
    }

    // Extract value
    const char *value_start = start;
    const char *value_end = strchr(value_start, ')');
    if (!value_end) {
        fprintf(stderr, "Error: Expected ')' in line: %s\n", line);
        exit(EXIT_FAILURE);
    }
    size_t value_len = value_end - value_start;
    char *value = malloc(value_len + 1);
    if (!value) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    strncpy(value, value_start, value_len);
    value[value_len] = '\0';

    // Set output parameters
    *out_name = name;
    *out_value = value;
}

static void parse_section_header(FILE *fp, ElfBinary *binary, int shdr_index) {
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    Elf64_Shdr *current_shdr = &binary->shdrs[shdr_index];

    while ((read = getline(&line, &len, fp)) != -1) {
        // Trim leading whitespace
        char *inner_trimmed_line = line;
        while (isspace((unsigned char)*inner_trimmed_line)) {
            inner_trimmed_line++;
        }

        // Check for end of section_header
        if (strcmp(inner_trimmed_line, ")\n") == 0 || strcmp(inner_trimmed_line, ")") == 0) {
            break;
        }

        // Parse the field
        char *field_name = NULL;
        char *field_value = NULL;
        parse_field(inner_trimmed_line, &field_name, &field_value);

        // Process the field based on its name
        if (strcmp(field_name, "sh_name") == 0) {
            current_shdr->sh_name = (Elf64_Word)strtoul(field_value, NULL, 0);
        } else if (strcmp(field_name, "sh_name_str") == 0) {
            size_t value_len = strlen(field_value);
            if (field_value[0] == '\"' && field_value[value_len - 1] == '\"') {
                field_value[value_len - 1] = '\0';
                binary->section_names[shdr_index] = strdup(field_value + 1);
                if (!binary->section_names[shdr_index]) {
                    perror("strdup");
                    exit(EXIT_FAILURE);
                }
            } else {
                fprintf(stderr, "Error: Invalid format for sh_name_str: %s\n", field_value);
                exit(EXIT_FAILURE);
            }
        } else if (strcmp(field_name, "sh_type") == 0) {
            current_shdr->sh_type = get_sh_type_value(field_value);
        } else if (strcmp(field_name, "sh_flags") == 0) {
            current_shdr->sh_flags = get_sh_flags_value(field_value);
        } else if (strcmp(field_name, "sh_addr") == 0) {
            current_shdr->sh_addr = strtoul(field_value, NULL, 0);
        } else if (strcmp(field_name, "sh_offset") == 0) {
            current_shdr->sh_offset = strtoul(field_value, NULL, 0);
        } else if (strcmp(field_name, "sh_size") == 0) {
            current_shdr->sh_size = strtoul(field_value, NULL, 0);
        } else if (strcmp(field_name, "sh_link") == 0) {
            current_shdr->sh_link = (Elf64_Word)strtoul(field_value, NULL, 0);
        } else if (strcmp(field_name, "sh_info") == 0) {
            current_shdr->sh_info = (Elf64_Word)strtoul(field_value, NULL, 0);
        } else if (strcmp(field_name, "sh_addralign") == 0) {
            current_shdr->sh_addralign = strtoul(field_value, NULL, 0);
        } else if (strcmp(field_name, "sh_entsize") == 0) {
            current_shdr->sh_entsize = strtoul(field_value, NULL, 0);
        } else if (strcmp(field_name, "sh_data") == 0) {
            if (current_shdr->sh_type == SHT_NOBITS) {
                fprintf(stderr, "Warning: sh_data field for SHT_NOBITS section %s. Ignoring data.\n",
                        binary->section_names[shdr_index]);
            } else {
                if (strncmp(field_value, "#hex\"", 5) == 0) {
                    const char *hex_data = field_value + 5;
                    size_t hex_len = strlen(hex_data);

                    if (hex_len >= 1 && hex_data[hex_len - 1] == '\"') {
                        hex_len--;
                    } else {
                        fprintf(stderr, "Error: Invalid format for sh_data\n");
                        exit(EXIT_FAILURE);
                    }

                    size_t data_size = hex_len / 2;
                    unsigned char *data = malloc(data_size);
                    if (!data) {
                        perror("malloc");
                        exit(EXIT_FAILURE);
                    }

                    // Convert hex string to binary data
                    for (size_t i = 0; i < data_size; i++) {
                        char byte_str[3] = { hex_data[i * 2], hex_data[i * 2 + 1], '\0' };
                        data[i] = (unsigned char)strtoul(byte_str, NULL, 16);
                    }
                    binary->section_data[shdr_index] = data;

                    // Update sh_size if necessary
                    if (current_shdr->sh_size != data_size) {
                        fprintf(stderr, "Warning: sh_size mismatch for section %s. Expected %lu, got %lu. Updating sh_size.\n",
                                binary->section_names[shdr_index], current_shdr->sh_size, data_size);
                        current_shdr->sh_size = data_size;
                    }
                } else {
                    fprintf(stderr, "Error: sh_data does not start with #hex\"\n");
                    exit(EXIT_FAILURE);
                }
            }
        } else {
            fprintf(stderr, "Warning: Unknown field '%s' in section header\n", field_name);
        }

        free(field_name);
        free(field_value);
    }
    free(line);
}

static void parse_section_headers(FILE *fp, ElfBinary *binary) {
    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    int shdr_count = 0;
    int num_sections = binary->ehdr.e_shnum;

    binary->shdrs = calloc(num_sections, sizeof(Elf64_Shdr));
    binary->section_names = calloc(num_sections, sizeof(char *));
    binary->section_data = calloc(num_sections, sizeof(unsigned char *));
    if (!binary->shdrs || !binary->section_names || !binary->section_data) {
        perror("calloc");
        exit(EXIT_FAILURE);
    }

    while ((read = getline(&line, &len, fp)) != -1) {
        char *trimmed_line = line;
        while (isspace((unsigned char)*trimmed_line)) {
            trimmed_line++;
        }

        if (strncmp(trimmed_line, "(section_header", 15) == 0) {
            if (shdr_count >= num_sections) {
                fprintf(stderr, "Error: More section headers in Lisp file than specified in e_shnum\n");
                exit(EXIT_FAILURE);
            }
            parse_section_header(fp, binary, shdr_count);
            shdr_count++;
        } else if (strcmp(trimmed_line, ")\n") == 0 || strcmp(trimmed_line, ")") == 0) {
            break;
        }
    }

    if (shdr_count != num_sections) {
        fprintf(stderr, "Warning: Number of section headers parsed (%d) does not match e_shnum (%d)\n",
                shdr_count, num_sections);
        binary->ehdr.e_shnum = shdr_count;
    }

    free(line);
}

static void parse_lisp_representation(FILE *fp, ElfBinary *binary) {
    char line[256];
    int elf_header_parsed = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "(elf_header")) {
            parse_elf_header(fp, binary);
            elf_header_parsed = 1;
        } else if (strstr(line, "(program_headers")) {
            parse_program_headers(fp, binary);
        } else if (strstr(line, "(section_headers")) {
            if (!elf_header_parsed) {
                fprintf(stderr, "Error: ELF header must be parsed before section headers\n");
                exit(EXIT_FAILURE);
            }
            parse_section_headers(fp, binary);
        }
    }
}

void parse_lisp_file(const char *filename, ElfBinary *binary) {
    FILE *fp = open_lisp_file(filename);
    parse_lisp_representation(fp, binary);
    fclose(fp);
}

