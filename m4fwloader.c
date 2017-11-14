/*
 * m4fwloader - based on mqx_upload_on_m4SoloX
 *              from Giuseppe Pagano
 *               
 * Tool to control M4 AMP core from Linux user-space
 * 
 * Copyright (C) 2015-2016 Giuseppe Pagano <giuseppe.pagano@seco.com>
 * Copyright 2017 NXP
 * Copyright 2017 Fluke
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <ctype.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <stdint.h>

#include "elf_load.h"
#include "log.h"
#include "m4_util.h"

#define VERSION "1.0.0"
#define NAME_OF_UTILITY "i.MX M4 Loader"
#define HEADER NAME_OF_UTILITY " - M4 firmware loader v. " VERSION "\n"


// globals
int verbose = 0;
struct soc_specific socs[] = {
    {
        "i.MX7 Dual",
        IMX7D_SRC_M4RCR,
        IMX7D_START_CLEAR_MASK,
        IMX7D_START_SET_MASK,
        IMX7D_STOP_CLEAR_MASK,
        IMX7D_STOP_SET_MASK,
        IMX7D_MU_ATR1,

        imx7d_clk_enable,

        IMX7D_M4_BOOTROM
    },
    {
        "i.MX6 SoloX",
        IMX6SX_SRC_SCR,
        IMX6SX_STOP_CLEAR_MASK,
        IMX6SX_STOP_SET_MASK,
        IMX6SX_START_CLEAR_MASK,
        IMX6SX_START_SET_MASK,
        IMX6SX_MU_ATR1,

        imx6sx_clk_enable,

        IMX6SX_M4_BOOTROM
    }
};


// loads bin-format m4 firmwares
int load_m4_fw(int fd, int socid, char* filepath, unsigned int loadaddr)
{
    //int n;
    long size;
    FILE* fdf;
    //off_t target;
    char* filebuffer;
    void *map_base, *virt_addr;
    unsigned long stack, pc;

    fdf = fopen(filepath, "rb");
    fseek(fdf, 0, SEEK_END);
    size = ftell(fdf);
    fseek(fdf, 0, SEEK_SET);
    if (size > MAX_FILE_SIZE) {
        LogError("%s - File size too big, can't load: %ld > %d \n", NAME_OF_UTILITY, size, MAX_FILE_SIZE);
        return -2;
    }
    filebuffer = (char*)malloc((size_t)size + 1);
    if ((size_t)size != fread(filebuffer, sizeof(char), (size_t)size, fdf)) {
        free(filebuffer);
        return -2;
    }

    fclose(fdf);

    stack = (long unsigned)(filebuffer[0] | (filebuffer[1] << 8) | (filebuffer[2] << 16) | (filebuffer[3] << 24));
    pc = (long unsigned)(filebuffer[4] | (filebuffer[5] << 8) | (filebuffer[6] << 16) | (filebuffer[7] << 24));

    if (loadaddr == 0x0) {
        loadaddr = pc & 0xFFFF0000; /* Align */
    }
    LogVerbose("%s - FILENAME = %s; loadaddr = 0x%08x\n", NAME_OF_UTILITY, filepath, loadaddr);

    map_base = mmap(0, M4_DDR_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)(loadaddr & (long unsigned)~M4_DDR_MASK));
    LogVerbose("%s - start - end (0x%08lx - 0x%08lx)\n", NAME_OF_UTILITY, loadaddr & (long unsigned)~M4_DDR_MASK, (loadaddr & (long unsigned)~M4_DDR_MASK) + M4_DDR_SIZE);
    virt_addr = (unsigned char*)map_base + (loadaddr & M4_DDR_MASK);
    memcpy(virt_addr, filebuffer, (size_t)size);
    munmap(map_base, M4_DDR_SIZE);

    LogVerbose("Will set PC and STACK...");
    set_stack_pc(fd, socid, stack, pc);
    LogVerbose("...Done\n");

    free(filebuffer);

    return size;
}

// loads elf-format m4 firmwares
int load_m4_fw_elf(int fd, int socid, char* filepath)
{
    long size;
    FILE* fdf;
    char* filebuffer;
    unsigned long stack, pc;

    fdf = fopen(filepath, "rb");
    fseek(fdf, 0, SEEK_END);
    size = ftell(fdf);
    fseek(fdf, 0, SEEK_SET);
    filebuffer = (char*)malloc((size_t)size + 1);
    if ((size_t)size != fread(filebuffer, sizeof(char), (size_t)size, fdf)) {
        free(filebuffer);
        return -2;
    }

    fclose(fdf);

    if (!valid_elf_image(filebuffer)) {
        free(filebuffer);
        return -1;
    }

    stack = 0x0;
    pc = load_elf_image_phdr(fd, filebuffer);
    if (!pc)
        return -2;

    LogVerbose("Will set PC and STACK...");
    // on boot, the m4 startup corrects the stack to the right value
    // additionally, it moves the tcm segement from where the
    //  elf loads it (ddr) to the actual tcm
    set_stack_pc(fd, socid, stack, pc);
    LogVerbose("...Done\n");

    free(filebuffer);

    return size;
}

void validate(int fd, char* filepath, unsigned int loadaddr)
{
    int n;
    int good = 1;
    long size;
    FILE* fdf;
    char* filebuffer;
    char* filebuffer2;
    void *map_base, *virt_addr;

    fdf = fopen(filepath, "rb");
    fseek(fdf, 0, SEEK_END);
    size = ftell(fdf);
    fseek(fdf, 0, SEEK_SET);
    if (size > MAX_FILE_SIZE) {
        LogError("%s - File size too big, can't load: %ld > %d \n", NAME_OF_UTILITY, size, MAX_FILE_SIZE);
        return;
    }
    filebuffer = (char*)malloc((size_t)size + 1);
    if ((size_t)size != fread(filebuffer, sizeof(char), (size_t)size, fdf)) {
        free(filebuffer);
        return;
    }

    fclose(fdf);

    LogVerbose("%s - FILENAME = %s; loadaddr = 0x%08x\n", NAME_OF_UTILITY, filepath, loadaddr);

    // Read back and validate
    filebuffer2 = (char*)malloc((size_t)size + 1);
    map_base = mmap(0, M4_DDR_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)(loadaddr & (long unsigned)~M4_DDR_MASK));
    virt_addr = (unsigned char*)map_base + (loadaddr & M4_DDR_MASK);
    memcpy(filebuffer2, virt_addr, (size_t)size);
    munmap(map_base, M4_DDR_SIZE);

    for (n = 0; n < size; n++) {
        if (filebuffer[n] != filebuffer2[n]) {
            printf("Readback does not match at 0x%x. File: %x mem: %x\n", loadaddr + (unsigned int)n, filebuffer[n], filebuffer2[n]);
            good = 0;
        }
    }
    if (good) {
        printf("File verified\n");
    }

    free(filebuffer);
    free(filebuffer2);
}

int get_board_id(void)
{
    int i;
    char out[512];
    int result = -1;
    FILE* fp;

    fp = fopen("/proc/cpuinfo", "r");
    if (fp == NULL)
        return result;

    while (fgets(out, sizeof(out) - 1, fp) != NULL) {
        if (strstr(out, "Hardware")) {
            for (i = 0; (unsigned long)i < (sizeof(socs) / sizeof(struct soc_specific)); i++) {
                if (strstr(out, socs[i].detect_name)) {
                    result = i;
                    break;
                }
            }
            break;
        }
    }

    fclose(fp);
    return result;
}

int main(int argc, char** argv)
{
    int fd;
    //int n;
    unsigned long loadaddr;
    char* p;
    //char m4IsStopped = 0;
    //char m4IsRunning = 0;
    //int m4TraceFlags = 0;
    //int m4Retry;
    char* filepath = argv[1];
    int currentSoC = -1;

    if (argc < 2) {
        LogError(HEADER);
        LogError("-- %s -- \nUsage:\n"
                 "%s [filename.bin] [--verbose]  # loads new firmware\n"
                 "or: %s stop                    # holds the auxiliary core in reset\n"
                 "or: %s start                   # releases the auxiliary core from reset\n"
                 "or: %s kick [n]                # triggers interrupt on RPMsg virtqueue n\n",
            NAME_OF_UTILITY, argv[0], argv[0], argv[0], argv[0]);
        return RETURN_CODE_ARGUMENTS_ERROR;
    }

    currentSoC = get_board_id();
    if (currentSoC == -1) {
        LogError(HEADER);
        LogError("Board is not supported.\n");
        return RETURN_CODE_ARGUMENTS_ERROR;
    }

    fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd < 0) {
        LogError(HEADER);
        LogError("Could not open /dev/mem, are you root?\n");
        return RETURN_CODE_ARGUMENTS_ERROR;
    }

    /* PARTIAL COMMANDS */
    if (!strcmp(argv[1], "stop")) {
        stop_cpu(fd, currentSoC);
        return RETURN_CODE_OK;
    }
    else if (!strcmp(argv[1], "start")) {
        start_cpu(fd, currentSoC);
        return RETURN_CODE_OK;
    }
    else if (!strcmp(argv[1], "kick")) {
        if (argc < 3) {
            LogError(HEADER);
            LogError("%s - Usage: %s kick {vq_id to kick}\n", NAME_OF_UTILITY, argv[0]);
            return RETURN_CODE_ARGUMENTS_ERROR;
        }
        rpmsg_mu_kick(fd, currentSoC, (unsigned int)strtoul(argv[2], &p, 16));
        return RETURN_CODE_OK;
    }
    else if (!strcmp(argv[1], "validate")) {
        if (argc < 3) {
            LogError(HEADER);
            LogError("%s - Usage: %s [yourfwname.bin] [--verbose]\n", NAME_OF_UTILITY, argv[0]);
            return RETURN_CODE_ARGUMENTS_ERROR;
        }
        filepath = argv[2];
        if (access(filepath, F_OK) == -1) {
            LogError("File %s not found.\n", argv[1]);
            return RETURN_CODE_ARGUMENTS_ERROR;
        }
        loadaddr = M4_DDR_ADDR;
        validate(fd, filepath, (unsigned int)loadaddr);
        return RETURN_CODE_OK;
    }

    /* FW LOADING */
    if (argc < 2) {
        LogError(HEADER);
        LogError("%s - Usage: %s [yourfwname.bin] [--verbose]\n", NAME_OF_UTILITY, argv[0]);
        return RETURN_CODE_ARGUMENTS_ERROR;
    }

    if (access(filepath, F_OK) == -1) {
        LogError("File %s not found.\n", argv[1]);
        return RETURN_CODE_ARGUMENTS_ERROR;
    }

    //loadaddr = strtoul(argv[2], &p, 16);
    loadaddr = M4_DDR_ADDR;

    if (argc == 3) {
        if (!strcmp(argv[2], "--verbose")) {
            verbose = 1;
        }
        else {
            LogError(HEADER);
            LogError("%s - Usage: %s [yourfwname.bin] [--verbose]\n", NAME_OF_UTILITY, argv[0]);
            return RETURN_CODE_ARGUMENTS_ERROR;
        }
    }

    LogVerbose("LoadAddr is: %lX\n", loadaddr);
    LogVerbose("Will stop CPU now...\n");
    stop_cpu(fd, currentSoC);
    LogVerbose("Will ungate M4 clock source...\n");
    ungate_m4_clk(fd, currentSoC);
    LogVerbose("Will load M4 firmware...\n");
    if (load_m4_fw_elf(fd, currentSoC, filepath) == -1) {
        LogVerbose("Not an elf file, falling back to bin\n");
        load_m4_fw(fd, currentSoC, filepath, (unsigned int)loadaddr);
    }
    LogVerbose("Will start CPU now...\n");
    start_cpu(fd, currentSoC);
    LogVerbose("Done!\n");

    close(fd);
    return RETURN_CODE_OK;
}
