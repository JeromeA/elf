#ifndef LISP_PARSER_H
#define LISP_PARSER_H

#include "elf.h"

void parse_lisp_file(const char *filename, ElfBinary *binary);

#endif /* LISP_PARSER_H */
