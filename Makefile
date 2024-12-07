
CFLAGS = -Wall -Wextra -pedantic -g3
LDFLAGS = -lcapstone

TARGETS = elf-decode elf-encode

ELF_DECODE_SOURCES = elf_decode.c decoder.c elf_reader.c lisp_writer.c elf.c elf_defaults.c common.c
ELF_DECODE_OBJECTS = $(ELF_DECODE_SOURCES:.c=.o)

ELF_ENCODE_SOURCES = elf_encode.c encoder.c lisp_parser.c elf_writer.c elf.c elf_defaults.c common.c
ELF_ENCODE_OBJECTS = $(ELF_ENCODE_SOURCES:.c=.o)

HEADERS := $(wildcard *.h)

.PHONY: all clean paste

all: $(TARGETS)

elf-decode: $(ELF_DECODE_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

elf-encode: $(ELF_ENCODE_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(ELF_ENCODE_OBJECTS) $(ELF_DECODE_OBJECTS) $(TARGETS)

paste:
	rm -f paste_code.txt
	for file in Makefile $(ELF_ENCODE_SOURCES) $(ELF_DECODE_SOURCES) $(HEADERS); do \
		echo "=== $$file ===" >> paste_code.txt; \
		cat $$file >> paste_code.txt; \
		echo "" >> paste_code.txt; \
	done
	grep ^[^[:space:]] paste_code.txt > paste_outline.txt

mat: all
	./elf-decode elf-decode t.lisp
	@echo "--> Successful decode"
	./elf-encode t.lisp t.elf
	@echo "--> Successful encode"
	cmp -l elf-decode t.elf
	@echo "--> Successful cmp"
