
CFLAGS = -Wall -Wextra -pedantic -g3
TARGET = elf
SOURCES = elf.c decode.c encode.c
OBJECTS = $(SOURCES:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(OBJECTS) $(TARGET)

