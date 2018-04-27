/***************************************************************************
 *   Copyright (C) 2011 by Andreas Fritiofson                              *
 *   andreas.fritiofson@gmail.com                                          *
 *   Copyright (C) 2013 by Roman Dmitrienko                                *
 *   me@iamroman.org                                                       *
 *   Copyright (C) 2017 by Ng Mow Song                                     *
 *   mowsong@gmail.com                                                     *
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
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

/*
 * To assemble:
 * arm-none-eabi-gcc -c gct301s.S
 *
 * To disassemble:
 * arm-none-eabi-objdump -S gct301s.o
 */
	.text
	.syntax unified
	.cpu cortex-m0
	.thumb
	.thumb_func

	/* Params:
	 * r0 - flash base (in), status (out)
	 * r1 - count (word-32bit)
	 * r2 - workarea start
	 * r3 - workarea end
	 * r4 - target address
	 * Clobbered:
	 * r5 - rp
	 * r6 - wp, tmp
	 * r7 - tmp
	 */

/* offsets of registers from flash reg base for GCT301S */
#define GCT301S_FLASH_PROGADDR  0x010
#define GCT301S_FLASH_PROGDATA  0x014
#define GCT301S_FLASH_PROG      0x018
#define GCT301S_FLASH_IF        0x020

wait_fifo:
	ldr     r6, [r2, #0]                        /* read wp */
	cmp     r6, #0                              /* abort if wp == 0 */
	beq     exit
	ldr     r5, [r2, #4]                        /* read rp */
	cmp     r5, r6                              /* wait until rp != wp */
	beq     wait_fifo

	str     r4, [r0, #GCT301S_FLASH_PROGADDR]   /* store address in PROGADDR */
	
    ldrb    r6, [r5]                            /* store data in PROGDATA !!!byte!!! */
    str     r6, [r0, #GCT301S_FLASH_PROGDATA]   
   
	ldr     r6, [r0, #GCT301S_FLASH_IF]

    movs    r6, #1                              /* set MPROG */
    str     r6, [r0, #GCT301S_FLASH_PROG]

	adds    r5, #1                              /* rp++ */
	adds    r4, #1                              /* target_address++ */

busy:                                           /* wait until IF flag is set */
	ldr     r6, [r0, #GCT301S_FLASH_IF]
	movs    r7, #1
	tst     r6, r7
	beq     busy

	cmp     r5, r3                              /* wrap rp at end of buffer */
	bcc     no_wrap
	mov     r5, r2
	adds    r5, #8

no_wrap:
	str     r5, [r2, #4]                        /* store rp */
	subs    r1, r1, #1                          /* decrement byte count */
	cmp     r1, #0
	beq     exit                                /* loop if not done */
	b       wait_fifo

exit:
	mov     r0, r6                              /* return status in r0 */
	bkpt    #0
