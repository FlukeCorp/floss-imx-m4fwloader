#pragma once

// Utilities for ELF loading i.mx7d m4 firmware
//int arch_auxiliary_core_up(u32 stack, u32 pc);
int valid_elf_image(char* addr);
unsigned long load_elf_image_phdr(int fd, char *addr);
