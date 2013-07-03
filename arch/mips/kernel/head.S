/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 1994, 1995 Waldorf Electronics
 * Written by Ralf Baechle and Andreas Busse
 * Copyright (C) 1994 - 99, 2003, 06 Ralf Baechle
 * Copyright (C) 1996 Paul M. Antoine
 * Modified for DECStation and hence R3000 support by Paul M. Antoine
 * Further modifications by David S. Miller and Harald Koerfgen
 * Copyright (C) 1999 Silicon Graphics, Inc.
 * Kevin Kissell, kevink@mips.com and Carsten Langgaard, carstenl@mips.com
 * Copyright (C) 2000 MIPS Technologies, Inc.  All rights reserved.
 */
#include <linux/init.h>
#include <linux/threads.h>

#include <asm/addrspace.h>
#include <asm/asm.h>
#include <asm/asmmacro.h>
#include <asm/irqflags.h>
#include <asm/regdef.h>
#include <asm/pgtable-bits.h>
#include <asm/mipsregs.h>
#include <asm/stackframe.h>

#include <kernel-entry-init.h>

	/*
	 * For the moment disable interrupts, mark the kernel mode and
	 * set ST0_KX so that the CPU does not spit fire when using
	 * 64-bit addresses.  A full initialization of the CPU's status
	 * register is done later in per_cpu_trap_init().
	 */
	.macro	setup_c0_status set clr
	.set	push
#ifdef CONFIG_MIPS_MT_SMTC
	/*
	 * For SMTC, we need to set privilege and disable interrupts only for
	 * the current TC, using the TCStatus register.
	 */
	mfc0	t0, CP0_TCSTATUS
	/* Fortunately CU 0 is in the same place in both registers */
	/* Set TCU0, TMX, TKSU (for later inversion) and IXMT */
	li	t1, ST0_CU0 | 0x08001c00
	or	t0, t1
	/* Clear TKSU, leave IXMT */
	xori	t0, 0x00001800
	mtc0	t0, CP0_TCSTATUS
	_ehb
	/* We need to leave the global IE bit set, but clear EXL...*/
	mfc0	t0, CP0_STATUS
	or	t0, ST0_CU0 | ST0_EXL | ST0_ERL | \set | \clr
	xor	t0, ST0_EXL | ST0_ERL | \clr
	mtc0	t0, CP0_STATUS
#else
	mfc0	t0, CP0_STATUS
	or	t0, ST0_CU0|\set|0x1f|\clr
	xor	t0, 0x1f|\clr
	mtc0	t0, CP0_STATUS
	.set	noreorder
	sll	zero,3				# ehb
#endif
	.set	pop
	.endm

	.macro	setup_c0_status_pri
#ifdef CONFIG_64BIT
	setup_c0_status ST0_KX 0
#else
	setup_c0_status 0 0		# CP0_Status[4:0] 置0，CU0 置1，其他位不变
#endif
	.endm

	.macro	setup_c0_status_sec
#ifdef CONFIG_64BIT
	setup_c0_status ST0_KX ST0_BEV
#else
	setup_c0_status 0 ST0_BEV
#endif
	.endm

#ifndef CONFIG_NO_EXCEPT_FILL
	/*
	 * Reserved space for exception handlers.
	 * Necessary for machines which link their kernels at KSEG0.
	 */
	.fill	0x400
#endif

EXPORT(_stext)

#ifdef CONFIG_BOOT_RAW
	/*
	 * Give us a fighting chance of running if execution beings at the
	 * kernel load address.	 This is needed because this platform does
	 * not have a ELF loader yet.
	 */
FEXPORT(__kernel_entry)
	j	kernel_entry
#endif

	__REF

/* 声明函数 kernel_entry,函数的堆栈为16byte，返回地址保存在$sp寄存器,宏NESTED()定义在asm.h*/
NESTED(kernel_entry, 16, sp)			# kernel entry point
	/*
	 * 某些MIPS CPU需要额外的设置一些控制寄存器，和具体的平台相关，一般为空宏；
     * 某些多核MIPS，启动时所有的core的入口一起指向kernel_entry，然后在该宏里分叉，
     * boot core 继续往下，其它的则不停的判断循环，直到boot core 唤醒之	
     */
	kernel_entry_setup			# cpu specific setup

	setup_c0_status_pri		    #设置cp0_status寄存器

	/* We might not get launched at the address the kernel is linked to,
	   so we jump there.  */
	PTR_LA	t0, 0f
	jr	t0
0:

/*
 * 宏定义   CONFIG_MIPS_MT_SMTC 是使用多核的  SMTC Linux 时定义的。
 * 一般情况下不考虑。 MIPS已经开发出  SMP Linux的改进版，叫做SMTC(线程上下文对称多处理) Linux。 
 * SMTC Linux能理解轻量级  TC 的概念，并能因此减少某些与SMP Linux相关的开销
 */
#ifdef CONFIG_MIPS_MT_SMTC
	/*
	 * In SMTC kernel, "CLI" is thread-specific, in TCStatus.
	 * We still need to enable interrupts globally in Status,
	 * and clear EXL/ERL.
	 *
	 * TCContext is used to track interrupt levels under
	 * service in SMTC kernel. Clear for boot TC before
	 * allowing any interrupts.
	 */
	mtc0	zero, CP0_TCCONTEXT

	mfc0	t0, CP0_STATUS
	ori	t0, t0, 0xff1f
	xori	t0, t0, 0x001e
	mtc0	t0, CP0_STATUS
#endif /* CONFIG_MIPS_MT_SMTC */

	/* 清除BSS段，清0 变量__bss_start和__bss_stop 在连接文件arch/mips/kernel/vmlinux.lds 中定义 */
	PTR_LA		t0, __bss_start		# clear .bss
	LONG_S		zero, (t0)
	PTR_LA		t1, __bss_stop - LONGSIZE
1:
	PTR_ADDIU	t0, LONGSIZE
	LONG_S		zero, (t0)
	bne		t0, t1, 1b

	LONG_S		a0, fw_arg0		# firmware arguments
	LONG_S		a1, fw_arg1		# bootloader会将要传给内核的参数写在a0~a4里,此处为将参数保存在fw_arg0~fw_arg3四个变量里
	LONG_S		a2, fw_arg2
	LONG_S		a3, fw_arg3

	MTC0		zero, CP0_CONTEXT	# clear context register #清除CP0的context register,#这个寄存器用来保存页表的起始地
	PTR_LA		$28, init_thread_union	 #初始化gp,指向一个union，THREAD_SIZE大小，最低处是一个thread_info 结构 
	/* Set the SP after an empty pt_regs.   # _THREAD_SIZE = THREAD_SIZE */
	PTR_LI		sp, _THREAD_SIZE - 32 - PT_SIZE
	/* 
	 * 设置$sp寄存器,堆栈指针.$sp = (init_thread_union 的地址)+_THREAD_SIZE - 32 的得出
	 * $sp 指向这个  union  结构的结尾地址-32 字节地址 
	 */
	PTR_ADDU	sp, $28				 #sp指向这个union结构的最高低32B处
	back_to_back_c0_hazard
	set_saved_sp	sp, t0, t1		# 把#这个cpu核的堆栈地址$sp保存到kernelsp[NR_CPUS]数组
	PTR_SUBU	sp, 4 * SZREG		# init stack pointer

	j		start_kernel			# gp,sp #设置好可以进入 C语言环境了
	END(kernel_entry)

#ifdef CONFIG_SMP
/*
 * SMP slave cpus entry point.	Board specific code for bootstrap calls this
 * function after setting up the stack and gp registers.
 */
NESTED(smp_bootstrap, 16, sp)
#ifdef CONFIG_MIPS_MT_SMTC
	/*
	 * Read-modify-writes of Status must be atomic, and this
	 * is one case where CLI is invoked without EXL being
	 * necessarily set. The CLI and setup_c0_status will
	 * in fact be redundant for all but the first TC of
	 * each VPE being booted.
	 */
	DMT	10	# dmt t2 /* t0, t1 are used by CLI and setup_c0_status() */
	jal	mips_ihb
#endif /* CONFIG_MIPS_MT_SMTC */
	setup_c0_status_sec
	smp_slave_setup
#ifdef CONFIG_MIPS_MT_SMTC
	andi	t2, t2, VPECONTROL_TE
	beqz	t2, 2f
	EMT		# emt
2:
#endif /* CONFIG_MIPS_MT_SMTC */
	j	start_secondary
	END(smp_bootstrap)
#endif /* CONFIG_SMP */
