#include "encoder.h"
#include "lisp_parser.h"
#include "elf_writer.h"
#include "elf.h"
#include <string.h>

void encode_elf(const char *filename) {
    ElfBinary binary;
    memset(&binary, 0, sizeof(ElfBinary));

    parse_lisp_file(filename, &binary);
    write_elf_binary(&binary);

    free_elf_binary(&binary);
}
