
CFLAGS = -Wall -Wextra -pedantic -g3
TARGET = elf
SOURCES = elf.c decoder.c elf_reader.c lisp_writer.c encoder.c lisp_parser.c elf_writer.c
OBJECTS = $(SOURCES:.c=.o)

.PHONY: all clean paste

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(OBJECTS) $(TARGET)

paste:
	rm -f paste_code.txt
	for file in Makefile $(SOURCES) $(HEADERS); do \
		echo "=== $$file ===" >> paste_code.txt; \
		cat $$file >> paste_code.txt; \
		echo "" >> paste_code.txt; \
	done
