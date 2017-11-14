#include "elf_load.h"

// adapted from u-boot elf loader
// see u-boot/common/cmd_bootaux.c

//#include <asm/arch-mx7/imx-regs.h>
#include <elf.h> // should be the same elf.h that u-boot uses
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include "log.h"

struct memorymap {
    unsigned long auxcore;
    unsigned long host;
    unsigned long size;
};

static const struct memorymap hostmap[] = {
    { .auxcore = 0x00000000, .host = 0x00180000, .size = 0x8000 },
    { .auxcore = 0x00180000, .host = 0x00180000, .size = 0x8000 },
    { .auxcore = 0x1fff8000, .host = 0x007f8000, .size = 0x8000 },
    { .auxcore = 0x20000000, .host = 0x00800000, .size = 0x8000 },
    { .auxcore = 0x20180000, .host = 0x00180000, .size = 0x8000 },
    { .auxcore = 0x00900000, .host = 0x00900000, .size = 0x20000 },
    { .auxcore = 0x20200000, .host = 0x00900000, .size = 0x20000 },
    { .auxcore = 0x00920000, .host = 0x00920000, .size = 0x20000 },
    { .auxcore = 0x20220000, .host = 0x00920000, .size = 0x20000 },
    { .auxcore = 0x00940000, .host = 0x00940000, .size = 0x20000 },
    { .auxcore = 0x20240000, .host = 0x00940000, .size = 0x20000 },
    { .auxcore = 0x10000000, .host = 0x80000000, .size = 0x0fff0000 },
    //{ .auxcore = 0x80000000, .host = 0x80000000, .size = 0xe0000000 },
    // m4 only has 2MB of ddr available to it
    { .auxcore = 0x80000000, .host = 0x80000000, .size = 0x00200000 },
    { /* sentinel */ }
};

/*
 * Get memory map by auxiliary core memory address
 */
static const struct memorymap *get_host_mapping(unsigned long auxcore)
{
    const struct memorymap *m4map = hostmap;

    while (m4map) {
        if (m4map->auxcore <= auxcore &&
            m4map->auxcore + m4map->size > auxcore)
            return m4map;
        m4map++;
    }

    return NULL;
}

/*
 * A very simple elf loader, assumes the image is valid, returns the
 * entry point address.
 */
unsigned long load_elf_image_phdr(int fd, char *addr)
{
    Elf32_Ehdr *ehdr; /* Elf header structure pointer */
    Elf32_Phdr *phdr; /* Program header structure pointer */
    int i;

    ehdr = (Elf32_Ehdr *)addr;
    phdr = (Elf32_Phdr *)(addr + ehdr->e_phoff);

    /* Load each program header */
    for (i = 0; i < ehdr->e_phnum; ++i, ++phdr) {
        const struct memorymap *m4map = get_host_mapping(phdr->p_paddr);
        char *dst, *virt_dst, *src, *map_base;

        if (phdr->p_type != PT_LOAD)
            continue;

        if (!m4map) {
            LogError("Invalid aux core address: %08x", phdr->p_paddr);
            return 0;
        }

        // copy segment to its destination
        if (phdr->p_filesz > m4map->size) {
            LogError("Elf segment too large for memory region");
            return 0;
        }

        // need to map memory region to work through fd
        map_base = mmap(0, m4map->size, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
                (off_t)(m4map->host));

        dst = (char*)(phdr->p_paddr - m4map->auxcore) + m4map->host;
        virt_dst = map_base + (phdr->p_paddr - m4map->auxcore);
        src = (char*)addr + phdr->p_offset;

        if (phdr->p_filesz) {
            // note, we are logging the actual address not the mapped one
            LogVerbose("copy segment start %p size 0x%08x\n", dst, phdr->p_filesz);
            memcpy(virt_dst, src, phdr->p_filesz);
        }
        if (phdr->p_filesz != phdr->p_memsz) {
            memset(virt_dst + phdr->p_filesz, 0x00,
                   phdr->p_memsz - phdr->p_filesz);
        }

        // todo do we need to flush cache?
        /*
        flush_cache((unsigned long)dst & (unsigned long)~(CONFIG_SYS_CACHELINE_SIZE-1),
                ALIGN(phdr->p_filesz, CONFIG_SYS_CACHELINE_SIZE));
        */
        munmap(map_base, m4map->size);
    }

    return ehdr->e_entry;
}

#define IS_ELF(ehdr) ((ehdr).e_ident[EI_MAG0] == ELFMAG0 && \
              (ehdr).e_ident[EI_MAG1] == ELFMAG1 && \
              (ehdr).e_ident[EI_MAG2] == ELFMAG2 && \
              (ehdr).e_ident[EI_MAG3] == ELFMAG3)

/* Determine if a valid ELF image exists at the given memory location.
 */
int valid_elf_image(char* addr)
{
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *) addr;

    if (!IS_ELF(*ehdr)) {
        LogVerbose("## No elf image at address %p\n", addr);
        return 0;
    }

    if (ehdr->e_type != ET_EXEC) {
        LogVerbose("## Not a 32-bit elf image at address %p\n", addr);
        return 0;
    }

    return 1;
}

/*
int arch_auxiliary_core_up(u32 stack, u32 pc)
{
    struct src *src_reg = (struct src *)SRC_BASE_ADDR;

    // Set the stack and pc to M4 bootROM
    writel(stack, M4_BOOTROM_BASE_ADDR);
    writel(pc, M4_BOOTROM_BASE_ADDR + 4);

    // Enable M4
    setbits_le32(&src_reg->m4rcr, 0x00000008);
    clrbits_le32(&src_reg->m4rcr, 0x00000001u);

    return 0;
}
*/

