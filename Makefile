
CFLAGS = -Wall -Wextra -pedantic -g3
TARGET = elf
SOURCES = elf.c decoder.c elf_reader.c lisp_writer.c encoder.c lisp_parser.c elf_writer.c
OBJECTS = $(SOURCES:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(OBJECTS) $(TARGET)

