#pragma once

#include <stdint.h>

// Utilities for ELF loading i.mx7d m4 firmware
//int arch_auxiliary_core_up(u32 stack, u32 pc);
int valid_elf_image(char* addr);
uint32_t load_elf_image_phdr(int fd, char *addr);
