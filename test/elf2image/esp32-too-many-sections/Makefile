# Makefile for generating and compiling an Xtensa-ESP32 ELF file that has a lot
# (too many) sections.
#
# To generate the C file and compile it, simply use the following command:
# make

# Adjustable parameters
BASH=/bin/bash
SECTIONS_COUNT=350

# Do not touch the following variables
CC=xtensa-esp32-elf-gcc
CFLAGS=-W -std=c99
LDFLAGS=-nostdlib -ffunction-sections -fdata-sections
OBJ=esp32-too-many-sections.o
BIN=esp32-too-many-sections.elf
SRC=esp32-too-many-sections.c

# The following command will generate the C file to compile.
# This is the simplest way to have a working and easily maintainable
# C file as it is almost only way out repetitions.
define generate_c_code =
    # Generate the constants, one per section.
    # Is it necessary to align the sections on an 16-byte bounds in order
    # to prevent esptool to merge them while generating the binary.
    # Indeed, by aligning them, there will be padding between them.
    echo "Generating $(SRC) ..."
    echo "// This has file been automatically generated, please check Makefile for\
more information." > $(SRC); \
    for i in {1..$(SECTIONS_COUNT)}; \
    do \
        echo "const int number$$i __attribute__ ((section (\".NUM$$i\"), aligned((16)))) = $$i;" >> $(SRC) ;\
    done;
    echo -e "\n" >> $(SRC) ; \
    echo "int _start(void) {" >> $(SRC) ; \
    echo "    volatile long int res =" >> $(SRC) ; \
    for i in {1..$(SECTIONS_COUNT)}; \
    do \
        echo "        (unsigned int) number$$i +" >> $(SRC) ;\
    done;
    # Adding 0 at the end it simpler than making a special case for the last
    # loop iteration
    echo "        0;" >> $(SRC) ;
    echo "    return res;" >> $(SRC) ;
    echo "}" >> $(SRC) ;
endef

.PHONY: all clean generate-src

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

# By default, make uses sh as script langage, use bash to generate the C file
$(SRC): SHELL:=$(BASH)
$(SRC):
	@$(generate_c_code)

%.o: %.c
	$(CC) -c -o $@ $^ $(CFLAGS)

clean:
	rm -f $(SRC) $(BIN) $(OBJ)
