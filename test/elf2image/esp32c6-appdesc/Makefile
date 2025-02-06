CC = riscv32-esp-elf-gcc
CFLAGS = -Os -ffreestanding -nostdlib
LDFLAGS = -T esp32c6-appdesc.ld

TARGET = esp32c6-appdesc.elf
SRC = main.c
OBJ = main.o

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)