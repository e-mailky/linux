/*
 * arch/arm/mm/highmem.c -- ARM highmem support
 *
 * Author:	Nicolas Pitre
 * Created:	september 8, 2008
 * Copyright:	Marvell Semiconductors Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/highmem.h>
#include <linux/interrupt.h>
#include <asm/fixmap.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#include "mm.h"

void *kmap(struct page *page)
{
	might_sleep();
	if (!PageHighMem(page))
		return page_address(page);
	return kmap_high(page);
}
EXPORT_SYMBOL(kmap);

void kunmap(struct page *page)
{
    /**
     * 不可能在中断中调用kmap，因此也不可能在中断中解除映射。
     * 这里用BUG_ON来确保检测是否有这种错误情况出现 
     */
	BUG_ON(in_interrupt());
	if (!PageHighMem(page))
		return;
	kunmap_high(page);
}
EXPORT_SYMBOL(kunmap);

/* 建立内核临时映射 */
void *kmap_atomic(struct page *page)
{
	unsigned int idx;
	unsigned long vaddr;
	void *kmap;
	int type;

    /**
     * 这里其实是禁止抢占: 禁止抢占的目的是为了避免线程飘移到其他核，
     * 因为后面要使用smp_processor_id确定线程的所在CPU
     * 不同CPU占用的kmap虚拟地址空间不一样，读者可以认真思考一下为什么需要这样做。
     */
	pagefault_disable();
	if (!PageHighMem(page))/* 如果页面不是高端内存 */
		return page_address(page);/* 直接返回其线性地址即可，没有必要进行kmap映射 */

#ifdef CONFIG_DEBUG_HIGHMEM
	/*
	 * There is no cache coherency issue when non VIVT, so force the
	 * dedicated kmap usage for better debugging purposes in that case.
	 */
	if (!cache_is_vivt())
		kmap = NULL;
	else
#endif
        /**
         * 在获得锁的情况下，获取页面的kmap地址，这里主要是防止不同任务、
         * 不同CPU上对同一个页面进行多次映射 
         */
		kmap = kmap_high_get(page);
    /**
     * 如果其他地方已经映射了该页，则在kmap_high_get中已经增加了映射计数，
     * 这里直接返回其虚拟地址即可 */
	if (kmap)
		return kmap;

	type = kmap_atomic_idx_push(); /* 递增本CPU上可用的kmap虚拟地址索引号 */

    /* 每个CPU上的kmap虚拟地址空间不同，这里是计算本CPU可用的地址索引号 */
	idx = type + KM_TYPE_NR * smp_processor_id();
	vaddr = __fix_to_virt(FIX_KMAP_BEGIN + idx); /* 将kmap地址索引号转换为可用的虚拟地址 */
#ifdef CONFIG_DEBUG_HIGHMEM
	/*
	 * With debugging enabled, kunmap_atomic forces that entry to 0.
	 * Make sure it was indeed properly unmapped.
	 */
	BUG_ON(!pte_none(get_top_pte(vaddr)));
#endif
	/*
	 * When debugging is off, kunmap_atomic leaves the previous mapping
	 * in place, so the contained TLB flush ensures the TLB is updated
	 * with the new mapping.
	 */ /* 为虚拟地址建立pte页表项 */
	set_top_pte(vaddr, mk_pte(page, kmap_prot));

	return (void *)vaddr;
}
EXPORT_SYMBOL(kmap_atomic);

/* 撤销内核临时映射 */
void __kunmap_atomic(void *kvaddr)
{
    /* 将虚拟地址对齐到页边界 */
	unsigned long vaddr = (unsigned long) kvaddr & PAGE_MASK;
	int idx, type;

    /**
     * FIXADDR_START是kmap_atomic映射的最小的虚拟地址，这里验证一下虚拟地址，
     * 确保它确实是由kmap_atomic而不是kmap映射出来的 
     */
	if (kvaddr >= (void *)FIXADDR_START) {
        /* 获得上一次调用kmap_atomic占用的虚拟地址空间索引号 */
		type = kmap_atomic_idx();
        /* 计算该索引号在整个kmap虚拟地址空间中的索引 */
		idx = type + KM_TYPE_NR * smp_processor_id();

		if (cache_is_vivt())
			__cpuc_flush_dcache_area((void *)vaddr, PAGE_SIZE);
#ifdef CONFIG_DEBUG_HIGHMEM
		BUG_ON(vaddr != __fix_to_virt(FIX_KMAP_BEGIN + idx));
		set_top_pte(vaddr, __pte(0));
#else
		(void) idx;  /* to kill a warning */
#endif
         /**
          * 其实这里什么也没有做，仅仅是递减了本CPU上的虚拟地址空间索引号，
          * 也就是说下次调用kmap_atomic时，占用本次释放的虚拟地址 */
		kmap_atomic_idx_pop();
    /* 判断虚拟地址空间是否是kmap占用的空间 */
	} else if (vaddr >= PKMAP_ADDR(0) && vaddr < PKMAP_ADDR(LAST_PKMAP)) {
		/* this address was obtained through kmap_high_get() */
        /* 如果是kmap的地址空间，则调用者应当调用kunmap，这里实现一个容错处理*/
		kunmap_high(pte_page(pkmap_page_table[PKMAP_NR(vaddr)]));
	}
    /**
     * 打开抢占，在kmap_atomic函数中关闭了抢占，这里打开。 
     * 换句话说，在kmap_atomic和kunmap_atomic之间，都是关抢占的。
     */	
    pagefault_enable();
}
EXPORT_SYMBOL(__kunmap_atomic);

void *kmap_atomic_pfn(unsigned long pfn)
{
	unsigned long vaddr;
	int idx, type;

	pagefault_disable();

	type = kmap_atomic_idx_push();
	idx = type + KM_TYPE_NR * smp_processor_id();
	vaddr = __fix_to_virt(FIX_KMAP_BEGIN + idx);
#ifdef CONFIG_DEBUG_HIGHMEM
	BUG_ON(!pte_none(get_top_pte(vaddr)));
#endif
	set_top_pte(vaddr, pfn_pte(pfn, kmap_prot));

	return (void *)vaddr;
}

struct page *kmap_atomic_to_page(const void *ptr)
{
	unsigned long vaddr = (unsigned long)ptr;

	if (vaddr < FIXADDR_START)
		return virt_to_page(ptr);

	return pte_page(get_top_pte(vaddr));
}
