/* modification for GCT301S 
 *
 * ngms
 * 2017 Oct 23
 */

/***************************************************************************
 *   Copyright (C) 2005 by Dominic Rath                                    *
 *   Dominic.Rath@gmx.de                                                   *
 *                                                                         *
 *   Copyright (C) 2008 by Spencer Oliver                                  *
 *   spen@spen-soft.co.uk                                                  *
 *                                                                         *
 *   Copyright (C) 2011 by Andreas Fritiofson                              *
 *   andreas.fritiofson@gmail.com                                          *
 *                                                                         *
 *   Copyright (C) 2013 by Roman Dmitrienko                                *
 *   me@iamroman.org                                                       *
 *                                                                         *
 *   Copyright (C) 2014 Nemui Trinomius                                    *
 *   nemuisan_kawausogasuki@live.jp                                        *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>. *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "imp.h"
#include <helper/binarybuffer.h>
#include <target/algorithm.h>
#include <target/armv7m.h>
#include <target/cortex_m.h>

/* keep family IDs in decimal */

#define EFM32_FLASH_ERASE_TMO           100
#define EFM32_FLASH_WDATAREADY_TMO      100
#define EFM32_FLASH_WRITE_TMO           100


#define EFM32_MSC_INFO_BASE             0x0fe00000

#define EFM32_MSC_USER_DATA             EFM32_MSC_INFO_BASE
#define EFM32_MSC_LOCK_BITS             (EFM32_MSC_INFO_BASE+0x4000)
#define EFM32_MSC_DEV_INFO              (EFM32_MSC_INFO_BASE+0x8000)

/* PAGE_SIZE is only present in Leopard, Giant and Wonder Gecko MCUs */
#define EFM32_MSC_DI_PAGE_SIZE          (EFM32_MSC_DEV_INFO+0x1e7)
#define EFM32_MSC_DI_FLASH_SZ           (EFM32_MSC_DEV_INFO+0x1f8)
#define EFM32_MSC_DI_RAM_SZ             (EFM32_MSC_DEV_INFO+0x1fa)
#define EFM32_MSC_DI_PART_NUM           (EFM32_MSC_DEV_INFO+0x1fc)
#define EFM32_MSC_DI_PART_FAMILY        (EFM32_MSC_DEV_INFO+0x1fe)
#define EFM32_MSC_DI_PROD_REV           (EFM32_MSC_DEV_INFO+0x1ff)

#define EFM32_MSC_REGBASE               0x400c0000
#define EFM32_MSC_WRITECTRL             (EFM32_MSC_REGBASE+0x008)
#define EFM32_MSC_WRITECTRL_WREN_MASK   0x1
#define EFM32_MSC_WRITECMD              (EFM32_MSC_REGBASE+0x00c)
#define EFM32_MSC_WRITECMD_LADDRIM_MASK 0x1
#define EFM32_MSC_WRITECMD_ERASEPAGE_MASK 0x2
#define EFM32_MSC_WRITECMD_WRITEONCE_MASK 0x8
#define EFM32_MSC_ADDRB                 (EFM32_MSC_REGBASE+0x010)
#define EFM32_MSC_WDATA                 (EFM32_MSC_REGBASE+0x018)
#define EFM32_MSC_STATUS                (EFM32_MSC_REGBASE+0x01c)
#define EFM32_MSC_STATUS_BUSY_MASK      0x1
#define EFM32_MSC_STATUS_LOCKED_MASK    0x2
#define EFM32_MSC_STATUS_INVADDR_MASK   0x4
#define EFM32_MSC_STATUS_WDATAREADY_MASK 0x8
#define EFM32_MSC_STATUS_WORDTIMEOUT_MASK 0x10
#define EFM32_MSC_STATUS_ERASEABORTED_MASK 0x20
#define EFM32_MSC_LOCK                  (EFM32_MSC_REGBASE+0x03c)
#define EFM32_MSC_LOCK_LOCKKEY          0x1b71

#define GCT301S_CFLASH_REGBASE  0x40017000UL
#define GCT301S_DFLASH_REGBASE  0x40018000UL

#define GCT301S_CFLASH_KEY         (GCT301S_CFLASH_REGBASE+0x00)
#define GCT301S_CFLASH_NVRP        (GCT301S_CFLASH_REGBASE+0x04)
#define GCT301S_CFLASH_ERASCTR     (GCT301S_CFLASH_REGBASE+0x08)
#define GCT301S_CFLASH_ERA         (GCT301S_CFLASH_REGBASE+0x0C)
#define GCT301S_CFLASH_PROGADDR    (GCT301S_CFLASH_REGBASE+0x10)
#define GCT301S_CFLASH_PROGDATA    (GCT301S_CFLASH_REGBASE+0x14)
#define GCT301S_CFLASH_PROG        (GCT301S_CFLASH_REGBASE+0x18)
#define GCT301S_CFLASH_IE          (GCT301S_CFLASH_REGBASE+0x1C)
#define GCT301S_CFLASH_IF          (GCT301S_CFLASH_REGBASE+0x20)
#define GCT301S_CFLASH_TIME        (GCT301S_CFLASH_REGBASE+0x24)

#define GCT301S_FLASH_UNLOCK_KEY        0xC6A5
#define GCT301S_FLASH_NVRP_WRITE 0x5AA5
#define GCT301S_FLASH_NVRP_READ  0xA55A

#define GCT301S_FLASH_ERASE_TMO  100

#define GCT301S_CFLASH_IF_MASK    0x1

struct gct301s_flash_bank {
	int probed;
};

struct gct_info {
	uint16_t flash_sz_kib;
	uint16_t ram_sz_kib;
	uint16_t part_num;
	uint8_t part_family;
	uint8_t prod_rev;
	uint16_t page_size;
};

static int gct301s_write(struct flash_bank *bank, const uint8_t *buffer,
	uint32_t offset, uint32_t count);

static int gct301s_get_flash_size(struct flash_bank *bank, uint16_t *flash_sz)
{
  *flash_sz = 128;
  return ERROR_OK;
}

static int gct301s_get_ram_size(struct flash_bank *bank, uint16_t *ram_sz)
{
  *ram_sz = 6;
  return ERROR_OK;
}

static int gct301s_get_part_num(struct flash_bank *bank, uint16_t *pnum)
{
  *pnum = 0x0301;
  return ERROR_OK;
}

static int gct301s_get_part_family(struct flash_bank *bank, uint8_t *pfamily)
{
  *pfamily = 0x0;
  return ERROR_OK;
}

static int gct301s_get_prod_rev(struct flash_bank *bank, uint8_t *prev)
{
  *prev = 0x0;
  return ERROR_OK;
}

static int gct301s_read_info(struct flash_bank *bank,
	struct gct_info *gct_info)
{
	int ret;
	uint32_t cpuid = 0;

	memset(gct_info, 0, sizeof(struct gct_info));

	ret = target_read_u32(bank->target, CPUID, &cpuid);
	if (ERROR_OK != ret)
		return ret;

	if (((cpuid >> 4) & 0xfff) == 0xc20) {
		/* Cortex-M0 device */
	} else {
		LOG_ERROR("Target is not GCT301S Cortex-M0 Device");
		return ERROR_FAIL;
	}

	ret = gct301s_get_flash_size(bank, &(gct_info->flash_sz_kib));
	if (ERROR_OK != ret)
		return ret;

	ret = gct301s_get_ram_size(bank, &(gct_info->ram_sz_kib));
	if (ERROR_OK != ret)
		return ret;

	ret = gct301s_get_part_num(bank, &(gct_info->part_num));
	if (ERROR_OK != ret)
		return ret;

	ret = gct301s_get_part_family(bank, &(gct_info->part_family));
	if (ERROR_OK != ret)
		return ret;

	ret = gct301s_get_prod_rev(bank, &(gct_info->prod_rev));
	if (ERROR_OK != ret)
		return ret;
  
  gct_info->page_size = 256;
	
  return ERROR_OK;
}

/*
 * Helper to create a human friendly string describing a part
 */
static int gct301s_decode_info(struct gct_info *info, char *buf, int buf_size)
{
	int printed = 0;
#if 0
	switch (info->part_family) {
		case EZR_FAMILY_ID_WONDER_GECKO:
		case EZR_FAMILY_ID_LEOPARD_GECKO:
			printed = snprintf(buf, buf_size, "EZR32 ");
			break;
		default:
			printed = snprintf(buf, buf_size, "EFM32 ");
	}
#endif
  printed = snprintf(buf, buf_size, "GCT301S ");

	buf += printed;
	buf_size -= printed;

	if (0 >= buf_size)
		return ERROR_BUF_TOO_SMALL;
	
  return ERROR_OK;
}

/* flash bank gct <base> <size> 0 0 <target#>
 */
FLASH_BANK_COMMAND_HANDLER(gct301s_flash_bank_command)
{
	struct gct301s_flash_bank *gct301s_info;

	if (CMD_ARGC < 6)
		return ERROR_COMMAND_SYNTAX_ERROR;

	gct301s_info = malloc(sizeof(struct gct301s_flash_bank));

	bank->driver_priv = gct301s_info;
	gct301s_info->probed = 0;

	return ERROR_OK;
}

/* set or reset given bits in a register */
static int gct301s_set_reg_bits(struct flash_bank *bank, uint32_t reg,
	uint32_t bitmask, int set)
{
	int ret = 0;
	uint32_t reg_val = 0;

	ret = target_read_u32(bank->target, reg, &reg_val);
	if (ERROR_OK != ret)
		return ret;

	if (set)
		reg_val |= bitmask;
	else
		reg_val &= ~bitmask;

	return target_write_u32(bank->target, reg, reg_val);
}

static int gct301s_set_wren(struct flash_bank *bank, int write_enable)
{
	return gct301s_set_reg_bits(bank, EFM32_MSC_WRITECTRL,
		EFM32_MSC_WRITECTRL_WREN_MASK, write_enable);
}

static int gct301s_cflash_lock(struct flash_bank *bank, int lock)
{
  return target_write_u32(bank->target, GCT301S_CFLASH_KEY,
      (lock ? 0 : GCT301S_FLASH_UNLOCK_KEY));
  
}

static int gct301s_wait_status(struct flash_bank *bank, int timeout,
	uint32_t wait_mask, int wait_for_set)
{
	int ret = 0;
	uint32_t status = 0;

	while (1) {
		ret = target_read_u32(bank->target, GCT301S_CFLASH_IF, &status);
		if (ERROR_OK != ret)
			break;

		if (((status & wait_mask) == 0) && (0 == wait_for_set))
			break;
		else if (((status & wait_mask) != 0) && wait_for_set)
			break;

		if (timeout-- <= 0) {
			LOG_ERROR("timed out waiting for IF status");
			return ERROR_FAIL;
		}

		alive_sleep(1);
	}

	return ret;
}

static int gct301s_erase_page(struct flash_bank *bank, uint32_t addr)
{
	int ret = 0;
	uint32_t status = 0;

	LOG_INFO("erasing flash page at 0x%08" PRIx32, addr);
  
  ret = target_write_u32(bank->target, GCT301S_CFLASH_ERASCTR, (addr >> 8));
  if (ERROR_OK != ret)
    return ret;

  ret = target_write_u32(bank->target, GCT301S_CFLASH_ERA, 0x1);
	if (ERROR_OK != ret)
		return ret;

	return gct301s_wait_status(bank, GCT301S_FLASH_ERASE_TMO,
		GCT301S_CFLASH_IF_MASK, 1);

}

static int gct301s_erase(struct flash_bank *bank, int first, int last)
{
	struct target *target = bank->target;
	int i = 0;
	int ret = 0;

	if (TARGET_HALTED != target->state) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

  LOG_DEBUG("Enable flash write");
	ret = gct301s_cflash_lock(bank, 0);
	if (ERROR_OK != ret) {
		LOG_ERROR("Failed to enable flash write");
		return ret;
	}
  LOG_DEBUG("Flash write enabled");
  
  LOG_DEBUG("Flash erase started");
	
  for (i = first; i <= last; i++) {
		ret = gct301s_erase_page(bank, bank->sectors[i].offset);
		if (ERROR_OK != ret)
			LOG_ERROR("Failed to erase page %d", i);
	}
  
  LOG_DEBUG("Flash erase ended");
	
  ret = gct301s_cflash_lock(bank, 1);

	return ret;
}

static int gct301s_read_lock_data(struct flash_bank *bank)
{
	return ERROR_OK;
}

static int gct301s_write_lock_data(struct flash_bank *bank)
{
  return ERROR_OK;
}

static int gct301s_get_page_lock(struct flash_bank *bank, size_t page)
{
  return 0;
}

static int gct301s_set_page_lock(struct flash_bank *bank, size_t page, int set)
{
	return ERROR_OK;
}

static int gct301s_protect(struct flash_bank *bank, int set, int first, int last)
{
	struct target *target = bank->target;
	int i = 0;
	int ret = 0;

	if (!set) {
		LOG_ERROR("Erase device data to reset page locks");
		return ERROR_FAIL;
	}

	if (target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	for (i = first; i <= last; i++) {
		ret = gct301s_set_page_lock(bank, i, set);
		if (ERROR_OK != ret) {
			LOG_ERROR("Failed to set lock on page %d", i);
			return ret;
		}
	}

	ret = gct301s_write_lock_data(bank);
	if (ERROR_OK != ret) {
		LOG_ERROR("Failed to write LB page");
		return ret;
	}

	return ERROR_OK;
}

static int gct301s_write_block(struct flash_bank *bank, const uint8_t *buf,
	uint32_t offset, uint32_t count)
{
	struct target *target = bank->target;
	uint32_t buffer_size = 16384;
	struct working_area *write_algorithm;
	struct working_area *source;
	uint32_t address = bank->base + offset;
	struct reg_param reg_params[5];
	struct armv7m_algorithm armv7m_info;
	int ret = ERROR_OK;

	/* see contrib/loaders/flash/gct.S for src */
	static const uint8_t gct301s_flash_write_code[] = {
		/* #define EFM32_MSC_WRITECTRL_OFFSET      0x008 */
		/* #define EFM32_MSC_WRITECMD_OFFSET       0x00c */
		/* #define EFM32_MSC_ADDRB_OFFSET          0x010 */
		/* #define EFM32_MSC_WDATA_OFFSET          0x018 */
		/* #define EFM32_MSC_STATUS_OFFSET         0x01c */
		/* #define EFM32_MSC_LOCK_OFFSET           0x03c */

			0x15, 0x4e,    /* ldr     r6, =#0x1b71 */
			0xc6, 0x63,    /* str     r6, [r0, #EFM32_MSC_LOCK_OFFSET] */
			0x01, 0x26,    /* movs    r6, #1 */
			0x86, 0x60,    /* str     r6, [r0, #EFM32_MSC_WRITECTRL_OFFSET] */

		/* wait_fifo: */
			0x16, 0x68,    /* ldr     r6, [r2, #0] */
			0x00, 0x2e,    /* cmp     r6, #0 */
			0x22, 0xd0,    /* beq     exit */
			0x55, 0x68,    /* ldr     r5, [r2, #4] */
			0xb5, 0x42,    /* cmp     r5, r6 */
			0xf9, 0xd0,    /* beq     wait_fifo */

			0x04, 0x61,    /* str     r4, [r0, #EFM32_MSC_ADDRB_OFFSET] */
			0x01, 0x26,    /* movs    r6, #1 */
			0xc6, 0x60,    /* str     r6, [r0, #EFM32_MSC_WRITECMD_OFFSET] */
			0xc6, 0x69,    /* ldr     r6, [r0, #EFM32_MSC_STATUS_OFFSET] */
			0x06, 0x27,    /* movs    r7, #6 */
			0x3e, 0x42,    /* tst     r6, r7 */
			0x16, 0xd1,    /* bne     error */

		/* wait_wdataready: */
			0xc6, 0x69,    /* ldr     r6, [r0, #EFM32_MSC_STATUS_OFFSET] */
			0x08, 0x27,    /* movs    r7, #8 */
			0x3e, 0x42,    /* tst     r6, r7 */
			0xfb, 0xd0,    /* beq     wait_wdataready */

			0x2e, 0x68,    /* ldr     r6, [r5] */
			0x86, 0x61,    /* str     r6, [r0, #EFM32_MSC_WDATA_OFFSET] */
			0x08, 0x26,    /* movs    r6, #8 */
			0xc6, 0x60,    /* str     r6, [r0, #EFM32_MSC_WRITECMD_OFFSET] */

			0x04, 0x35,    /* adds    r5, #4 */
			0x04, 0x34,    /* adds    r4, #4 */

		/* busy: */
			0xc6, 0x69,    /* ldr     r6, [r0, #EFM32_MSC_STATUS_OFFSET] */
			0x01, 0x27,    /* movs    r7, #1 */
			0x3e, 0x42,    /* tst     r6, r7 */
			0xfb, 0xd1,    /* bne     busy */

			0x9d, 0x42,    /* cmp     r5, r3 */
			0x01, 0xd3,    /* bcc     no_wrap */
			0x15, 0x46,    /* mov     r5, r2 */
			0x08, 0x35,    /* adds    r5, #8 */

		/* no_wrap: */
			0x55, 0x60,    /* str     r5, [r2, #4] */
			0x01, 0x39,    /* subs    r1, r1, #1 */
			0x00, 0x29,    /* cmp     r1, #0 */
			0x02, 0xd0,    /* beq     exit */
			0xdb, 0xe7,    /* b       wait_fifo */

		/* error: */
			0x00, 0x20,    /* movs    r0, #0 */
			0x50, 0x60,    /* str     r0, [r2, #4] */

		/* exit: */
			0x30, 0x46,    /* mov     r0, r6 */
			0x00, 0xbe,    /* bkpt    #0 */

		/* LOCKKEY */
			0x71, 0x1b, 0x00, 0x00
	};

	/* flash write code */
	if (target_alloc_working_area(target, sizeof(gct301s_flash_write_code),
			&write_algorithm) != ERROR_OK) {
		LOG_WARNING("no working area available, can't do block memory writes");
		return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
	}

	ret = target_write_buffer(target, write_algorithm->address,
			sizeof(gct301s_flash_write_code), gct301s_flash_write_code);
	if (ret != ERROR_OK)
		return ret;

	/* memory buffer */
	while (target_alloc_working_area_try(target, buffer_size, &source) != ERROR_OK) {
		buffer_size /= 2;
		buffer_size &= ~3UL; /* Make sure it's 4 byte aligned */
		if (buffer_size <= 256) {
			/* we already allocated the writing code, but failed to get a
			 * buffer, free the algorithm */
			target_free_working_area(target, write_algorithm);

			LOG_WARNING("no large enough working area available, can't do block memory writes");
			return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
		}
	}

	init_reg_param(&reg_params[0], "r0", 32, PARAM_IN_OUT);	/* flash base (in), status (out) */
	init_reg_param(&reg_params[1], "r1", 32, PARAM_OUT);	/* count (word-32bit) */
	init_reg_param(&reg_params[2], "r2", 32, PARAM_OUT);	/* buffer start */
	init_reg_param(&reg_params[3], "r3", 32, PARAM_OUT);	/* buffer end */
	init_reg_param(&reg_params[4], "r4", 32, PARAM_IN_OUT);	/* target address */

	buf_set_u32(reg_params[0].value, 0, 32, EFM32_MSC_REGBASE);
	buf_set_u32(reg_params[1].value, 0, 32, count);
	buf_set_u32(reg_params[2].value, 0, 32, source->address);
	buf_set_u32(reg_params[3].value, 0, 32, source->address + source->size);
	buf_set_u32(reg_params[4].value, 0, 32, address);

	armv7m_info.common_magic = ARMV7M_COMMON_MAGIC;
	armv7m_info.core_mode = ARM_MODE_THREAD;

	ret = target_run_flash_async_algorithm(target, buf, count, 4,
			0, NULL,
			5, reg_params,
			source->address, source->size,
			write_algorithm->address, 0,
			&armv7m_info);

	if (ret == ERROR_FLASH_OPERATION_FAILED) {
		LOG_ERROR("flash write failed at address 0x%"PRIx32,
				buf_get_u32(reg_params[4].value, 0, 32));

		if (buf_get_u32(reg_params[0].value, 0, 32) &
				EFM32_MSC_STATUS_LOCKED_MASK) {
			LOG_ERROR("flash memory write protected");
		}

		if (buf_get_u32(reg_params[0].value, 0, 32) &
				EFM32_MSC_STATUS_INVADDR_MASK) {
			LOG_ERROR("invalid flash memory write address");
		}
	}

	target_free_working_area(target, source);
	target_free_working_area(target, write_algorithm);

	destroy_reg_param(&reg_params[0]);
	destroy_reg_param(&reg_params[1]);
	destroy_reg_param(&reg_params[2]);
	destroy_reg_param(&reg_params[3]);
	destroy_reg_param(&reg_params[4]);

	return ret;
}

static int gct301s_write_word(struct flash_bank *bank, uint32_t addr,
	uint32_t val)
{
	/* this function DOES NOT set WREN; must be set already */
	/* 1. write address to ADDRB
	   2. write LADDRIM
	   3. check status (INVADDR, LOCKED)
	   4. wait for WDATAREADY
	   5. write data to WDATA
	   6. write WRITECMD_WRITEONCE to WRITECMD
	   7. wait until !STATUS_BUSY
	 */

	/* FIXME: EFM32G ref states (7.3.2) that writes should be
	 * performed twice per dword */

	int ret = 0;
	uint32_t status = 0;

	/* if not called, GDB errors will be reported during large writes */
	keep_alive();

	ret = target_write_u32(bank->target, EFM32_MSC_ADDRB, addr);
	if (ERROR_OK != ret)
		return ret;

	ret = gct301s_set_reg_bits(bank, EFM32_MSC_WRITECMD,
		EFM32_MSC_WRITECMD_LADDRIM_MASK, 1);
	if (ERROR_OK != ret)
		return ret;

	ret = target_read_u32(bank->target, EFM32_MSC_STATUS, &status);
	if (ERROR_OK != ret)
		return ret;

	LOG_DEBUG("status 0x%" PRIx32, status);

	if (status & EFM32_MSC_STATUS_LOCKED_MASK) {
		LOG_ERROR("Page is locked");
		return ERROR_FAIL;
	} else if (status & EFM32_MSC_STATUS_INVADDR_MASK) {
		LOG_ERROR("Invalid address 0x%" PRIx32, addr);
		return ERROR_FAIL;
	}

	ret = gct301s_wait_status(bank, EFM32_FLASH_WDATAREADY_TMO,
		EFM32_MSC_STATUS_WDATAREADY_MASK, 1);
	if (ERROR_OK != ret) {
		LOG_ERROR("Wait for WDATAREADY failed");
		return ret;
	}

	ret = target_write_u32(bank->target, EFM32_MSC_WDATA, val);
	if (ERROR_OK != ret) {
		LOG_ERROR("WDATA write failed");
		return ret;
	}

	ret = target_write_u32(bank->target, EFM32_MSC_WRITECMD,
		EFM32_MSC_WRITECMD_WRITEONCE_MASK);
	if (ERROR_OK != ret) {
		LOG_ERROR("WRITECMD write failed");
		return ret;
	}

	ret = gct301s_wait_status(bank, EFM32_FLASH_WRITE_TMO,
		EFM32_MSC_STATUS_BUSY_MASK, 0);
	if (ERROR_OK != ret) {
		LOG_ERROR("Wait for BUSY failed");
		return ret;
	}

	return ERROR_OK;
}

static int gct301s_write(struct flash_bank *bank, const uint8_t *buffer,
		uint32_t offset, uint32_t count)
{
	struct target *target = bank->target;
	uint8_t *new_buffer = NULL;

	if (target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	if (offset & 0x3) {
		LOG_ERROR("offset 0x%" PRIx32 " breaks required 4-byte "
			"alignment", offset);
		return ERROR_FLASH_DST_BREAKS_ALIGNMENT;
	}

	if (count & 0x3) {
		uint32_t old_count = count;
		count = (old_count | 3) + 1;
		new_buffer = malloc(count);
		if (new_buffer == NULL) {
			LOG_ERROR("odd number of bytes to write and no memory "
				"for padding buffer");
			return ERROR_FAIL;
		}
		LOG_INFO("odd number of bytes to write (%" PRIu32 "), extending to %" PRIu32 " "
			"and padding with 0xff", old_count, count);
		memset(new_buffer, 0xff, count);
		buffer = memcpy(new_buffer, buffer, old_count);
	}

	uint32_t words_remaining = count / 4;
	int retval, retval2;

	/* unlock flash registers */
	gct301s_cflash_lock(bank, 0);
	retval = gct301s_set_wren(bank, 1);
	if (retval != ERROR_OK)
		goto cleanup;

	/* try using a block write */
	retval = gct301s_write_block(bank, buffer, offset, words_remaining);

	if (retval == ERROR_TARGET_RESOURCE_NOT_AVAILABLE) {
		/* if block write failed (no sufficient working area),
		 * we use normal (slow) single word accesses */
		LOG_WARNING("couldn't use block writes, falling back to single "
			"memory accesses");

		while (words_remaining > 0) {
			uint32_t value;
			memcpy(&value, buffer, sizeof(uint32_t));

			retval = gct301s_write_word(bank, offset, value);
			if (retval != ERROR_OK)
				goto reset_pg_and_lock;

			words_remaining--;
			buffer += 4;
			offset += 4;
		}
	}

reset_pg_and_lock:
	retval2 = gct301s_set_wren(bank, 0);
	gct301s_cflash_lock(bank, 1);
	if (retval == ERROR_OK)
		retval = retval2;

cleanup:
	if (new_buffer)
		free(new_buffer);

	return retval;
}

static int gct301s_probe(struct flash_bank *bank)
{
	struct gct301s_flash_bank *gct301s_info = bank->driver_priv;
	struct gct_info gct_mcu_info;
	int ret;
	int i;
	uint32_t base_address = 0x00000000;
	char buf[256];

	gct301s_info->probed = 0;

	ret = gct301s_read_info(bank, &gct_mcu_info);
	if (ERROR_OK != ret)
		return ret;

	ret = gct301s_decode_info(&gct_mcu_info, buf, sizeof(buf));
	if (ERROR_OK != ret)
		return ret;

	LOG_INFO("detected part: %s", buf);
	LOG_INFO("flash size = %dkbytes", gct_mcu_info.flash_sz_kib);
	LOG_INFO("flash page size = %dbytes", gct_mcu_info.page_size);

	assert(0 != gct_mcu_info.page_size);

	int num_pages = gct_mcu_info.flash_sz_kib * 1024 /
		gct_mcu_info.page_size;

	assert(num_pages > 0);

	if (bank->sectors) {
		free(bank->sectors);
		bank->sectors = NULL;
	}

	bank->base = base_address;
	bank->size = (num_pages * gct_mcu_info.page_size);
	bank->num_sectors = num_pages;

	ret = gct301s_read_lock_data(bank);
	if (ERROR_OK != ret) {
		LOG_ERROR("Failed to read LB data");
		return ret;
	}

	bank->sectors = malloc(sizeof(struct flash_sector) * num_pages);

	for (i = 0; i < num_pages; i++) {
		bank->sectors[i].offset = i * gct_mcu_info.page_size;
		bank->sectors[i].size = gct_mcu_info.page_size;
		bank->sectors[i].is_erased = -1;
		bank->sectors[i].is_protected = 1;
	}

	gct301s_info->probed = 1;

	return ERROR_OK;
}

static int gct301s_auto_probe(struct flash_bank *bank)
{
	struct gct301s_flash_bank *gct301s_info = bank->driver_priv;
	if (gct301s_info->probed)
		return ERROR_OK;
	return gct301s_probe(bank);
}

static int gct301s_protect_check(struct flash_bank *bank)
{
	struct target *target = bank->target;
	int ret = 0;
	int i = 0;

	if (target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	ret = gct301s_read_lock_data(bank);
	if (ERROR_OK != ret) {
		LOG_ERROR("Failed to read LB data");
		return ret;
	}

	assert(NULL != bank->sectors);

	for (i = 0; i < bank->num_sectors; i++)
		bank->sectors[i].is_protected = gct301s_get_page_lock(bank, i);

	return ERROR_OK;
}

static int get_gct301s_info(struct flash_bank *bank, char *buf, int buf_size)
{
	struct gct_info info;
	int ret = 0;

	ret = gct301s_read_info(bank, &info);
	if (ERROR_OK != ret) {
		LOG_ERROR("Failed to read GCT301S info");
		return ret;
	}

	return gct301s_decode_info(&info, buf, buf_size);
}

COMMAND_HANDLER(gct301s_handle_debuglock_command)
{
	struct target *target = NULL;

	if (CMD_ARGC < 1)
		return ERROR_COMMAND_SYNTAX_ERROR;

	struct flash_bank *bank;
	int retval = CALL_COMMAND_HANDLER(flash_command_get_bank, 0, &bank);
	if (ERROR_OK != retval)
		return retval;

	struct gct301s_flash_bank *gct301s_info = bank->driver_priv;

	target = bank->target;

	if (target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	uint32_t *ptr;
	//ptr = gct301s_info->lb_page + 127;
	*ptr = 0;

	retval = gct301s_write_lock_data(bank);
	if (ERROR_OK != retval) {
		LOG_ERROR("Failed to write LB page");
		return retval;
	}

	command_print(CMD_CTX, "gct301s debug interface locked, reset the device to apply");

	return ERROR_OK;
}

static const struct command_registration gct301s_exec_command_handlers[] = {
	{
		.name = "debuglock",
		.handler = gct301s_handle_debuglock_command,
		.mode = COMMAND_EXEC,
		.usage = "bank_id",
		.help = "Lock the debug interface of the device.",
	},
	COMMAND_REGISTRATION_DONE
};

static const struct command_registration gct301s_command_handlers[] = {
	{
		.name = "gct",
		.mode = COMMAND_ANY,
		.help = "gct flash command group",
		.usage = "",
		.chain = gct301s_exec_command_handlers,
	},
	COMMAND_REGISTRATION_DONE
};

struct flash_driver gct301s_flash = {
	.name = "gct301s",
	.commands = gct301s_command_handlers,
	.flash_bank_command = gct301s_flash_bank_command,
	.erase = gct301s_erase,
	.protect = gct301s_protect,
	.write = gct301s_write,
	.read = default_flash_read,
	.probe = gct301s_probe,
	.auto_probe = gct301s_auto_probe,
	.erase_check = default_flash_blank_check,
	.protect_check = gct301s_protect_check,
	.info = get_gct301s_info,
};
