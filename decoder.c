#include "decoder.h"
#include "elf_reader.h"
#include "lisp_writer.h"
#include "elf.h"

void decode_elf(const char *input_filename, const char *output_filename) {
    ElfBinary binary;
    read_elf_binary(input_filename, &binary);
    output_lisp_representation(&binary, output_filename);
    free_elf_binary(&binary);
}
