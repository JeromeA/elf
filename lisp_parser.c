#include "elf.h"
#include "lisp_parser.h"
#include "common.h"
#include <stdbool.h>
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

/*
 * Helper function to read, trim a line, and determine if parsing should continue.
 * Empty lines and comments are skipped.
 * Return true if line/len is returning a useful line, false if there is nothing to read anymore.
 */
static bool get_line(FILE *fp, char **input, char **line, size_t *len) {
    while (true) {
        if (getline(input, len, fp) == -1) {
            return false; // EOF or read error
        }

        // Remove comments: trim everything after a semicolon ';'
        char *comment_pos = strchr(*input, ';');
        if (comment_pos) {
            *comment_pos = '\0';
        }

        // Trim leading whitespace
        *line = *input;
        while (isspace((unsigned char)**line)) {
            (*line)++;
        }

        // Trim trailing whitespace
        char *end = *line + strlen(*line) - 1;
        while (end >= *line && isspace((unsigned char)*end)) {
            *end = '\0';
            end--;
        }

        // Skip empty lines
        if (**line == '\0') {
            continue; // Read next line
        }

        // Stop if the line is a lone closing parenthesis
        if (strcmp(*line, ")") == 0) {
            return false;
        }

        return true; // Continue parsing
    }
}

/* Parses the ELF header from the Lisp representation with constants */
static void parse_elf_header(FILE *fp, ElfBinary *binary) {
    char *input = NULL;
    char *line = NULL;
    size_t len = 0;
    char name[64], value_str[128];

    while (get_line(fp, &input, &line, &len)) {
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
    free(input);
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
    char *input = NULL;
    char *line = NULL;
    size_t len;
    char name[64], value_str[128];

    while (get_line(fp, &input, &line, &len)) {
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
    free(input);
}

static void parse_program_headers(FILE *fp, ElfBinary *binary) {
    char *input = NULL;
    char *line = NULL;
    size_t len;
    int phdr_count = 0;
    int phdr_capacity = 4;

    binary->phdrs = xcalloc(phdr_capacity, sizeof(Elf64_Phdr));

    while (get_line(fp, &input, &line, &len)) {
        if (strncmp(line, "(program_header", 15) == 0) {
            if (phdr_count == phdr_capacity) {
                phdr_capacity *= 2;
                binary->phdrs = xrealloc(binary->phdrs, sizeof(Elf64_Phdr) * phdr_capacity);
            }
            Elf64_Phdr *current_phdr = &binary->phdrs[phdr_count];
            memset(current_phdr, 0, sizeof(Elf64_Phdr));

            parse_program_header(fp, current_phdr);
            phdr_count++;
        }
    }

    if (binary->ehdr.e_phnum == 0) {
        binary->ehdr.e_phnum = phdr_count;
    } else if (binary->ehdr.e_phnum != phdr_count) {
        fprintf(stderr, "Error: e_phnum mismatch\n");
        exit(EXIT_FAILURE);
    }

    free(input);
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
    char *name = xmalloc(name_len + 1);
    strncpy(name, name_start, name_len);
    name[name_len] = '\0';

    // Skip whitespace before value
    while (isspace((unsigned char)*start)) {
        start++;
    }

    // Extract value
    const char *value_start = start;
    const char *value_end = NULL;
    if (value_start[0] == 0) {
        value_end = value_start;
    } else if (value_start[0] == '"') {
        value_end = strchr(value_start + 1, '"');
        if (!value_end) {
            fprintf(stderr, "Error: Expected terminating '\"' in line: %s\n", line);
            exit(EXIT_FAILURE);
        }
        value_end++;
    } else {
        value_end = strchr(value_start, ')');
        if (!value_end) {
            fprintf(stderr, "Error: Expected terminating ')' in line: %s\n", line);
            exit(EXIT_FAILURE);
        }
    }
    size_t value_len = value_end - value_start;
    char *value = xmalloc(value_len + 1);
    strncpy(value, value_start, value_len);
    value[value_len] = '\0';

    // Set output parameters
    *out_name = name;
    *out_value = value;
}

static unsigned char* parse_sh_data(FILE *fp, size_t *out_size) {
    unsigned char *data = NULL;
    char *input = NULL;
    char *line = NULL;
    size_t len = 0;
    size_t data_capacity = 0;
    size_t data_size = 0;

    while (get_line(fp, &input, &line, &len)) {
        char *attr_name = NULL;
        char *attr_value = NULL;
        parse_field(line, &attr_name, &attr_value);

        if (strcmp(attr_name, "string") == 0) {
            // Extract the string without quotes
            size_t value_len = strlen(attr_value);
            if (attr_value[0] != '\"' || attr_value[value_len - 1] != '\"') {
                fprintf(stderr, "Error: Invalid format for string attribute: %s\n", attr_value);
                exit(EXIT_FAILURE);
            }
            attr_value[value_len - 1] = '\0';
            char *str = strdup(attr_value + 1);
            if (!str) {
                perror("strdup");
                exit(EXIT_FAILURE);
            }
            size_t str_len = strlen(str) + 1; // Include null terminator

            // Append to data buffer
            if (data_size + str_len > data_capacity) {
                data_capacity = (data_capacity == 0) ? 64 : data_capacity * 2;
                data = xrealloc(data, data_capacity);
            }
            memcpy(&data[data_size], str, str_len);
            data_size += str_len;
            free(str);
        } else if (strcmp(attr_name, "binary") == 0) {
            // Expecting binary data in the format x20404F4F0012
            if (strncmp(attr_value, "x", 1) != 0) {
                fprintf(stderr, "Error: Invalid format for binary attribute: %s\n", attr_value);
                exit(EXIT_FAILURE);
            }
            const char *hex_str = attr_value + 1;
            size_t hex_len = strlen(hex_str);
            if (hex_len % 2 != 0) {
                fprintf(stderr, "Error: Binary hex string length must be even: %s\n", hex_str);
                exit(EXIT_FAILURE);
            }
            size_t bin_len = hex_len / 2;
            unsigned char *bin_data = xmalloc(bin_len);
            for (size_t i = 0; i < bin_len; i++) {
                char byte_str[3] = { hex_str[i * 2], hex_str[i * 2 + 1], '\0' };
                bin_data[i] = (unsigned char)strtoul(byte_str, NULL, 16);
            }

            // Replace existing data
            free(data);
            data = bin_data;
            data_size = bin_len;
            data_capacity = bin_len;
        } else {
            fprintf(stderr, "Error: Unknown attribute '%s' in sh_data\n", attr_name);
            exit(EXIT_FAILURE);
        }

        free(attr_name);
        free(attr_value);
    }

    free(input);
    *out_size = data_size;
    return data;
}

static unsigned char* parse_notes(FILE *fp, size_t *out_size) {
    unsigned char *data = NULL;
    size_t data_capacity = 0;
    size_t data_size = 0;
    char *input = NULL;
    char *line = NULL;
    size_t len = 0;

    while (get_line(fp, &input, &line, &len)) {
        // Expecting a (note ...) block
        if (strncmp(line, "(note", 5) != 0) {
            fprintf(stderr, "Error: Expected '(note' but got: %s\n", line);
            exit(EXIT_FAILURE);
        }

        // Initialize note fields
        char *name = NULL;
        Elf64_Word type = 0;
        unsigned char *descriptor = NULL;
        size_t descsz = 0;

        // Parse fields within (note ...)
        while (get_line(fp, &input, &line, &len)) {
            char *field_name = NULL;
            char *field_value = NULL;
            parse_field(line, &field_name, &field_value);

            if (strcmp(field_name, "name") == 0) {
                size_t value_len = strlen(field_value);
                if (field_value[0] != '\"' || field_value[value_len - 1] != '\"') {
                    fprintf(stderr, "Error: Invalid format for note name: %s\n", field_value);
                    exit(EXIT_FAILURE);
                }
                // Allocate and copy name without quotes
                field_value[value_len - 1] = '\0';
                name = strdup(field_value + 1);
                if (!name) {
                    perror("strdup");
                    exit(EXIT_FAILURE);
                }
            } else if (strcmp(field_name, "type") == 0) {
                type = (Elf64_Word)atoi(field_value);
            } else if (strcmp(field_name, "descriptor") == 0) {
                if (strncmp(field_value, "x", 1) != 0) {
                    fprintf(stderr, "Error: Descriptor must start with 'x': %s\n", field_value);
                    exit(EXIT_FAILURE);
                }
                const char *hex_str = field_value + 1;
                size_t hex_len = strlen(hex_str);
                if (hex_len % 2 != 0) {
                    fprintf(stderr, "Error: Descriptor hex string length must be even: %s\n", hex_str);
                    exit(EXIT_FAILURE);
                }
                descsz = hex_len / 2;
                descriptor = xmalloc(descsz);
                for (size_t i = 0; i < descsz; i++) {
                    char byte_str[3] = { hex_str[i * 2], hex_str[i * 2 + 1], '\0' };
                    descriptor[i] = (unsigned char)strtoul(byte_str, NULL, 16);
                }
            } else {
                fprintf(stderr, "Warning: Unknown field '%s' in note\n", field_name);
            }

            free(field_name);
            free(field_value);
        }

        if (!name) {
            fprintf(stderr, "Error: Note missing 'name' field\n");
            exit(EXIT_FAILURE);
        }
        if (!descriptor) {
            fprintf(stderr, "Error: Note missing 'descriptor' field\n");
            exit(EXIT_FAILURE);
        }

        // Prepare Elf64_Nhdr
        Elf64_Nhdr nhdr;
        nhdr.n_namesz = strlen(name) + 1;
        nhdr.n_descsz = descsz;
        nhdr.n_type = type;

        // Calculate padding
        size_t name_padding = (4 - (nhdr.n_namesz % 4)) % 4;
        size_t desc_padding = (4 - (nhdr.n_descsz % 4)) % 4;

        // Calculate total size for the note
        size_t total_size = sizeof(Elf64_Nhdr) + nhdr.n_namesz + name_padding + nhdr.n_descsz + desc_padding;

        // Ensure data buffer has enough space
        if (data_size + total_size > data_capacity) {
            size_t new_capacity = data_capacity ? data_capacity * 2 : 128;
            while (new_capacity < data_size + total_size) {
                new_capacity *= 2;
            }
            data = xrealloc(data, new_capacity);
            data_capacity = new_capacity;
        }

        // Append nhdr
        memcpy(&data[data_size], &nhdr, sizeof(Elf64_Nhdr));
        data_size += sizeof(Elf64_Nhdr);

        // Append name
        memcpy(&data[data_size], name, nhdr.n_namesz);
        data_size += nhdr.n_namesz;
        // Append padding
        for (size_t i = 0; i < name_padding; i++) {
            data[data_size++] = 0x00;
        }

        // Append descriptor
        memcpy(&data[data_size], descriptor, nhdr.n_descsz);
        data_size += nhdr.n_descsz;
        // Append padding
        for (size_t i = 0; i < desc_padding; i++) {
            data[data_size++] = 0x00;
        }

        free(name);
        free(descriptor);
    }
    free(input);

    *out_size = data_size;
    return data;
}

static void parse_section_header(FILE *fp, ElfBinary *binary, int shdr_index) {
    char *input = NULL;
    char *line = NULL;
    size_t len = 0;
    Elf64_Shdr *current_shdr = &binary->shdrs[shdr_index];

    while (get_line(fp, &input, &line, &len)) {
        // Parse the field
        char *field_name = NULL;
        char *field_value = NULL;
        parse_field(line, &field_name, &field_value);

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
                fprintf(stderr, "Error: sh_data field for SHT_NOBITS section %s.\n", binary->section_names[shdr_index]);
                exit(EXIT_FAILURE);
            } else {
                if (field_value[0] != 0) {
                    fprintf(stderr, "Error: Expected '(sh_data' but got: %s\n", line);
                    exit(EXIT_FAILURE);
                }

                unsigned char *data = NULL;
                size_t data_size = 0;

                if (current_shdr->sh_type == SHT_NOTE) {
                    data = parse_notes(fp, &data_size);
                } else {
                    data = parse_sh_data(fp, &data_size);
                }

                binary->section_data[shdr_index] = data;
                current_shdr->sh_size = data_size;
            }
        } else {
            fprintf(stderr, "Warning: Unknown field '%s' in section header\n", field_name);
        }

        free(field_name);
        free(field_value);
    }
    free(input);
}

static void parse_section_headers(FILE *fp, ElfBinary *binary) {
    char *input = NULL;
    char *line = NULL;
    size_t len = 0;
    int shdr_count = 0;
    int shdr_capacity = 4;

    binary->shdrs = xcalloc(shdr_capacity, sizeof(Elf64_Shdr));
    binary->section_names = xcalloc(shdr_capacity, sizeof(char *));
    binary->section_data = xcalloc(shdr_capacity, sizeof(unsigned char *));

    while (get_line(fp, &input, &line, &len)) {
        if (strncmp(line, "(section_header", 15) == 0) {
            if (shdr_count == shdr_capacity) {
                shdr_capacity *= 2;
                binary->shdrs = xrealloc(binary->shdrs, sizeof(Elf64_Shdr) * shdr_capacity);
                binary->section_names = xrealloc(binary->section_names, sizeof(char *) * shdr_capacity);
                binary->section_data = xrealloc(binary->section_data, sizeof(unsigned char *) * shdr_capacity);
            }
            parse_section_header(fp, binary, shdr_count);
            shdr_count++;
        }
    }

    if (binary->ehdr.e_shnum == 0) {
        binary->ehdr.e_shnum = shdr_count;
    } else if (binary->ehdr.e_shnum != shdr_count) {
        fprintf(stderr, "Error: e_shnum mismatch\n");
        exit(EXIT_FAILURE);
    }

    free(input);
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

