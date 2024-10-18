#include "encoder.h"
#include "lisp_parser.h"
#include "elf_writer.h"
#include "elf.h"
#include "elf_defaults.h"
#include <string.h>

void encode_elf(const char *input_filename, const char *output_filename) {
    ElfBinary binary;
    memset(&binary, 0, sizeof(ElfBinary));

    parse_lisp_file(input_filename, &binary);
    compute_defaults(&binary);
    write_elf_binary(&binary, output_filename);

    free_elf_binary(&binary);
}
