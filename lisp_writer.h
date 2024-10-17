#ifndef LISP_WRITER_H
#define LISP_WRITER_H

#include "elf.h"

void output_lisp_representation(const ElfBinary *binary, const char *output_filename);

#endif /* LISP_WRITER_H */
