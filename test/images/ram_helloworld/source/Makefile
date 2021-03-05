# Makefile to compile the helloworld app for esptool tests

# Prefix for each cross compiler (can include a directory path)
# These can be overriden via environment variables or on the make command line
CROSS_8266 ?= xtensa-lx106-elf-
CROSS_32 ?= xtensa-esp32-elf-
CROSS_32S2 ?= xtensa-esp32s2-elf-
CROSS_32S3 ?= xtensa-esp32s3-elf-
CROSS_32C3 ?= riscv32-esp-elf-

# Pass V=1 to see the commands being executed by make
ifneq ("$(V)","1")
Q = @
endif

APP = hello_world
SRCS = main.c

BUILD_DIR = build

APP_ELF_8266 = $(BUILD_DIR)/$(APP)_8266.elf
APP_ELF_32 = $(BUILD_DIR)/$(APP)_32.elf
APP_ELF_32S2 = $(BUILD_DIR)/$(APP)_32s2.elf
APP_ELF_32S3_BETA_2 = $(BUILD_DIR)/$(APP)_32s3beta2.elf
APP_ELF_32S3_BETA_3 = $(BUILD_DIR)/$(APP)_32s3beta3.elf
APP_ELF_32C3 = $(BUILD_DIR)/$(APP)_32c3.elf

.PHONY: all clean

all: $(APP_ELF_8266) $(APP_ELF_32) $(APP_ELF_32S2)

$(BUILD_DIR):
	$(Q) mkdir $@

CFLAGS = -std=c99 -Wall -Werror -Os \
         -mtext-section-literals -mlongcalls -nostdlib -fno-builtin -flto \
         -Wl,-static -g -ffunction-sections -Wl,--gc-sections -Iinclude -Lld
CFLAGS_ESP32C3 = -std=c99 -Wall -Werror -Os \
		 -march=rv32imc -msmall-data-limit=0 \
         -nostdlib -fno-builtin -flto \
         -Wl,-static -g -ffunction-sections -Wl,--gc-sections -Iinclude -Lld
LDLIBS = -lgcc

$(APP_ELF_8266): $(SRCS) $(SRCS_8266) $(BUILD_DIR) ld/app_8266.ld | Makefile
	@echo "  CC(8266)   $^ -> $@"
	$(Q) $(CROSS_8266)gcc $(CFLAGS) -DESP8266=1 -Tapp_8266.ld -Wl,-Map=$(@:.elf=.map) -o $@ $(filter %.c, $^) $(LDLIBS)

$(APP_ELF_32): $(SRCS) $(BUILD_DIR) ld/app_32.ld | Makefile
	@echo "  CC(32)   $^ -> $@"
	$(Q) $(CROSS_32)gcc $(CFLAGS) -DESP32=1 -Tapp_32.ld -Wl,-Map=$(@:.elf=.map) -o $@ $(filter %.c, $^) $(LDLIBS)

$(APP_ELF_32S2): $(SRCS) $(BUILD_DIR) ld/app_32s2.ld
	@echo "  CC(32S2)   $^ -> $@"
	$(Q) $(CROSS_32S2)gcc $(CFLAGS) -DESP32S2=1 -Tapp_32s2.ld -Wl,-Map=$(@:.elf=.map) -o $@ $(filter %.c, $^) $(LDLIBS)

$(APP_ELF_32S3_BETA_2): $(SRCS) $(BUILD_DIR) ld/app_32s3_beta_2.ld
	@echo "  CC(32S3)   $^ -> $@"
	$(Q) $(CROSS_32S3)gcc $(CFLAGS) -DESP32S3=1 -Tapp_32s3.ld -Wl,-Map=$(@:.elf=.map) -o $@ $(filter %.c, $^) $(LDLIBS)

$(APP_ELF_32S3_BETA_3): $(SRCS) $(BUILD_DIR) ld/app_32s3_beta_3.ld
	@echo "  CC(32S3)   $^ -> $@"
	$(Q) $(CROSS_32S3)gcc $(CFLAGS) -DESP32S3=1 -Tapp_32s3.ld -Wl,-Map=$(@:.elf=.map) -o $@ $(filter %.c, $^) $(LDLIBS)

$(APP_ELF_32C3): $(SRCS) $(BUILD_DIR) ld/app_32c3.ld
	@echo "  CC(32C3)   $^ -> $@"
	$(Q) $(CROSS_32C3)gcc $(CFLAGS_ESP32C3) -DESP32C3=1 -Tapp_32c3.ld -Wl,-Map=$(@:.elf=.map) -o $@ $(filter %.c, $^) $(LDLIBS)

clean:
	$(Q) rm -rf $(BUILD_DIR)
