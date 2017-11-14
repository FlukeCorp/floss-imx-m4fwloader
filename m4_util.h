#pragma once

#include <stdint.h>

#define IMX7D_SRC_M4RCR          (0x3039000C) /* reset register */
#define IMX7D_STOP_CLEAR_MASK    (0xFFFFFF00)
#define IMX7D_STOP_SET_MASK      (0x000000AA)
#define IMX7D_START_CLEAR_MASK   (0xFFFFFFFF)
#define IMX7D_START_SET_MASK     (0x00000001)
#define IMX7D_MU_ATR1            (0x30AA0004) /* rpmsg_mu_kick_addr */
#define IMX7D_M4_BOOTROM         (0x00180000) 
#define IMX7D_CCM_ANALOG_PLL_480 (0x303600B0)
#define IMX7D_CCM_CCGR1          (0x30384010)

#define IMX6SX_SRC_SCR           (0x020D8000) /* reset register */
#define IMX6SX_STOP_CLEAR_MASK   (0xFFFFFFEF)
#define IMX6SX_STOP_SET_MASK     (0x00400000)
#define IMX6SX_START_CLEAR_MASK  (0xFFFFFFFF)
#define IMX6SX_START_SET_MASK    (0x00400010)
#define IMX6SX_MU_ATR1           (0x02294004) /* rpmsg_mu_kick_addr */
#define IMX6SX_M4_BOOTROM        (0x007F8000) 
#define IMX6SX_CCM_CCGR3         (0x020C4074)

#define MAP_SIZE 4096UL
#define MAP_MASK (MAP_SIZE - 1)
#define SIZE_4BYTE 4UL
#define SIZE_16BYTE 16UL
#define MAP_OCRAM_SIZE 64 * 1024
#define MAP_OCRAM_MASK (MAP_OCRAM_SIZE - 1)
#define MAX_RETRIES 8

#define M4_DDR_ADDR 0x80000000
#define M4_DDR_SIZE 0x200000
#define M4_DDR_MASK (M4_DDR_SIZE - 1)
#define MAX_FILE_SIZE M4_DDR_SIZE

#define RETURN_CODE_OK 0
#define RETURN_CODE_ARGUMENTS_ERROR 1
#define RETURN_CODE_M4STOP_FAILED 2
#define RETURN_CODE_M4START_FAILED 3

struct soc_specific {
    const char* detect_name;

    uint32_t src_m4reg_addr;

    uint32_t start_and;
    uint32_t start_or;
    uint32_t stop_and;
    uint32_t stop_or;

    uint32_t rpmsg_mu_kick_addr;

    void (*clk_enable)(int);

    uint32_t stack_pc_addr;
};

extern struct soc_specific socs[];

void regshow(uint32_t addr, const char* name, int fd);
void rpmsg_mu_kick(int fd, int socid, uint32_t vq_id);
void ungate_m4_clk(int fd, int socid);
void stop_cpu(int fd, int socid);
void start_cpu(int fd, int socid);
void set_stack_pc(int fd, int socid, unsigned int stack, unsigned int pc);
void imx6sx_clk_enable(int fd);
void imx7d_clk_enable(int fd);
