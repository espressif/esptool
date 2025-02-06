#include <stdint.h>

// This is the structure of the application description section in the binary image (taken from ESP-IDF).
typedef struct {
    uint32_t magic_word;
    uint32_t secure_version;
    uint32_t reserv1[2];
    char version[32];
    char project_name[32];
    char time[16];
    char date[16];
    char idf_ver[32];
    uint8_t app_elf_sha256[32];
    uint16_t min_efuse_blk_rev_full;
    uint16_t max_efuse_blk_rev_full;
    uint8_t mmu_page_size;
    uint8_t reserv3[3];
    uint32_t reserv2[18];
} esp_app_desc_t;

__attribute__((section(".flash.appdesc")))
esp_app_desc_t my_app_desc = {
    .magic_word = 0xABCD5432,
    .secure_version = 0xffffffff,
    .reserv1 = {0xffffffff, 0xffffffff},
    .version = "_______________________________",
    .project_name = "-------------------------------",
    .time = "xxxxxxxxxxxxxxx",
    .date = "yyyyyyyyyyyyyyy",
    .idf_ver = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
    .app_elf_sha256 = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    },
    .min_efuse_blk_rev_full = 0xffff,
    .max_efuse_blk_rev_full = 0xffff,
    .mmu_page_size = 0,
    .reserv3 = {0xff, 0xff, 0xff},
    .reserv2 = {
        0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
        0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
        0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
        0xffffffff, 0xffffffff, 0xffffffff
    },
};