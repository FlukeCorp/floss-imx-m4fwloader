#include "m4_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>

#include "log.h"

void regshow(uint32_t addr, const char* name, int fd)
{
    long unsigned target;
    void *map_base, *virt_addr;

    target = addr;
    map_base = mmap(0, MAP_SIZE, PROT_READ, MAP_SHARED, fd, (off_t)(target & ~MAP_MASK));
    virt_addr = (unsigned char*)map_base + (target & MAP_MASK);
    LogVerbose("%s (0x%08X): 0x%08lX\r\n", name, addr, *((unsigned long*)virt_addr));
    munmap(map_base, MAP_SIZE);
}

void rpmsg_mu_kick(int fd, int socid, uint32_t vq_id)
{
    long unsigned target;
    void *map_base, *virt_addr;

    if (!socs[socid].rpmsg_mu_kick_addr)
        return;

    target = socs[socid].rpmsg_mu_kick_addr;
    map_base = mmap(0, SIZE_4BYTE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)(target & ~MAP_MASK));
    virt_addr = (unsigned char*)map_base + (target & MAP_MASK);
    vq_id = (vq_id << 16);
    *((unsigned long*)virt_addr) = vq_id;
    munmap(map_base, SIZE_4BYTE);
}

void ungate_m4_clk(int fd, int socid)
{
    socs[socid].clk_enable(fd);
}

void stop_cpu(int fd, int socid)
{
    unsigned long read_result;
    unsigned long target;
    void *map_base, *virt_addr;

    if (!socs[socid].src_m4reg_addr)
        return;

    regshow(socs[socid].src_m4reg_addr, "STOP - before", fd);
    target = socs[socid].src_m4reg_addr;
    map_base = mmap(0, SIZE_4BYTE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)(target & ~MAP_MASK));
    virt_addr = (unsigned char*)map_base + (target & MAP_MASK);
    read_result = *((unsigned long*)virt_addr);
    *((unsigned long*)virt_addr) = (read_result & (socs[socid].stop_and)) | socs[socid].stop_or;
    munmap(virt_addr, SIZE_4BYTE);
    regshow(socs[socid].src_m4reg_addr, "STOP - after", fd);
}

void start_cpu(int fd, int socid)
{
    unsigned long read_result;
    unsigned long target;
    void *map_base, *virt_addr;

    if (!socs[socid].src_m4reg_addr)
        return;

    regshow(socs[socid].src_m4reg_addr, "START - before", fd);
    target = socs[socid].src_m4reg_addr;
    map_base = mmap(0, SIZE_4BYTE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)(target & ~MAP_MASK));
    virt_addr = (unsigned char*)map_base + (target & MAP_MASK);
    read_result = *((unsigned long*)virt_addr);
    *((unsigned long*)virt_addr) = (read_result & (socs[socid].start_and)) | socs[socid].start_or;
    munmap(virt_addr, SIZE_4BYTE);
    regshow(socs[socid].src_m4reg_addr, "START -after", fd);
}

void set_stack_pc(int fd, int socid, unsigned int stack, unsigned int pc)
{
    long unsigned target = socs[socid].stack_pc_addr;
    //unsigned long read_result;
    void *map_base, *virt_addr;
    map_base = mmap(0, SIZE_16BYTE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)(target & ~MAP_MASK));
    virt_addr = (unsigned char*)map_base + (target & MAP_MASK);
    *((unsigned long*)virt_addr) = stack;
    virt_addr = (unsigned char*)map_base + ((target + 0x4) & MAP_MASK);
    *((unsigned long*)virt_addr) = pc;
    munmap(map_base, SIZE_16BYTE);
}

void imx6sx_clk_enable(int fd)
{
    unsigned long target;
    unsigned long read_result;
    void *map_base, *virt_addr;

    LogVerbose("i.MX6SX specific function for M4 clock enabling!\n");

    regshow(IMX6SX_CCM_CCGR3, "CCM_CCGR3", fd);
    target = IMX6SX_CCM_CCGR3; /* M4 Clock gate*/
    map_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)(target & ~MAP_MASK));
    virt_addr = (unsigned char*)map_base + (target & MAP_MASK);
    read_result = *((unsigned long*)virt_addr);
    *((unsigned long*)virt_addr) = read_result | 0x0000000C;
    munmap(map_base, MAP_SIZE);
    regshow(IMX6SX_CCM_CCGR3, "CCM_CCGR3", fd);
    LogVerbose("CCM_CCGR3 done\n");
}

void imx7d_clk_enable(int fd)
{
    unsigned long target;
    //unsigned long read_result;
    void *map_base, *virt_addr;

    LogVerbose("i.MX7D specific function for M4 clock enabling!\n");

    regshow(IMX7D_CCM_ANALOG_PLL_480, "CCM_ANALOG_PLL_480", fd);
    /* Enable parent clock first! */
    target = IMX7D_CCM_ANALOG_PLL_480;
    map_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)(target & ~MAP_MASK));
    virt_addr = (unsigned char*)map_base + (target & MAP_MASK);
    /* clock enabled by clearing the bit!  */
    *((unsigned long*)virt_addr) = (*((unsigned long*)virt_addr)) & (unsigned long)(~(1 << 5));
    munmap(map_base, MAP_SIZE);
    regshow(IMX7D_CCM_ANALOG_PLL_480, "CCM_ANALOG_PLL_480", fd);
    LogVerbose("CCM_ANALOG_PLL_480 done\n");

    /* ENABLE CLK */
    regshow(IMX7D_CCM_CCGR1, "CCM1_CCGR1", fd);
    target = (off_t)(IMX7D_CCM_CCGR1+4); /* CCM_CCGR1_SET */
    map_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)(target & ~MAP_MASK));
    virt_addr = (unsigned char*)map_base + (target & MAP_MASK);
    *((unsigned long*)virt_addr) = 0x00000003;
    munmap(map_base, MAP_SIZE);
    regshow(IMX7D_CCM_CCGR1, "CCM1_CCGR1", fd);
    LogVerbose("CCM_CCGR1_SET done\n");
}

