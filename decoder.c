#include "decoder.h"
#include "elf_reader.h"
#include "lisp_writer.h"
#include "elf.h"

void decode_elf(const char *filename) {
    ElfBinary binary;
    read_elf_binary(filename, &binary);
    output_lisp_representation(&binary);
    free_elf_binary(&binary);
}
