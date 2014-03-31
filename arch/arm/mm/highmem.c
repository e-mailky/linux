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
     * ���������ж��е���kmap�����Ҳ���������ж��н��ӳ�䡣
     * ������BUG_ON��ȷ������Ƿ������ִ���������� 
     */
	BUG_ON(in_interrupt());
	if (!PageHighMem(page))
		return;
	kunmap_high(page);
}
EXPORT_SYMBOL(kunmap);

/* �����ں���ʱӳ�� */
void *kmap_atomic(struct page *page)
{
	unsigned int idx;
	unsigned long vaddr;
	void *kmap;
	int type;

    /**
     * ������ʵ�ǽ�ֹ��ռ: ��ֹ��ռ��Ŀ����Ϊ�˱����߳�Ʈ�Ƶ������ˣ�
     * ��Ϊ����Ҫʹ��smp_processor_idȷ���̵߳�����CPU
     * ��ͬCPUռ�õ�kmap�����ַ�ռ䲻һ�������߿�������˼��һ��Ϊʲô��Ҫ��������
     */
	pagefault_disable();
	if (!PageHighMem(page))/* ���ҳ�治�Ǹ߶��ڴ� */
		return page_address(page);/* ֱ�ӷ��������Ե�ַ���ɣ�û�б�Ҫ����kmapӳ�� */

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
         * �ڻ����������£���ȡҳ���kmap��ַ��������Ҫ�Ƿ�ֹ��ͬ����
         * ��ͬCPU�϶�ͬһ��ҳ����ж��ӳ�� 
         */
		kmap = kmap_high_get(page);
    /**
     * ��������ط��Ѿ�ӳ���˸�ҳ������kmap_high_get���Ѿ�������ӳ�������
     * ����ֱ�ӷ����������ַ���� */
	if (kmap)
		return kmap;

	type = kmap_atomic_idx_push(); /* ������CPU�Ͽ��õ�kmap�����ַ������ */

    /* ÿ��CPU�ϵ�kmap�����ַ�ռ䲻ͬ�������Ǽ��㱾CPU���õĵ�ַ������ */
	idx = type + KM_TYPE_NR * smp_processor_id();
	vaddr = __fix_to_virt(FIX_KMAP_BEGIN + idx); /* ��kmap��ַ������ת��Ϊ���õ������ַ */
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
	 */ /* Ϊ�����ַ����pteҳ���� */
	set_top_pte(vaddr, mk_pte(page, kmap_prot));

	return (void *)vaddr;
}
EXPORT_SYMBOL(kmap_atomic);

/* �����ں���ʱӳ�� */
void __kunmap_atomic(void *kvaddr)
{
    /* �������ַ���뵽ҳ�߽� */
	unsigned long vaddr = (unsigned long) kvaddr & PAGE_MASK;
	int idx, type;

    /**
     * FIXADDR_START��kmap_atomicӳ�����С�������ַ��������֤һ�������ַ��
     * ȷ����ȷʵ����kmap_atomic������kmapӳ������� 
     */
	if (kvaddr >= (void *)FIXADDR_START) {
        /* �����һ�ε���kmap_atomicռ�õ������ַ�ռ������� */
		type = kmap_atomic_idx();
        /* �����������������kmap�����ַ�ռ��е����� */
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
          * ��ʵ����ʲôҲû�����������ǵݼ��˱�CPU�ϵ������ַ�ռ������ţ�
          * Ҳ����˵�´ε���kmap_atomicʱ��ռ�ñ����ͷŵ������ַ */
		kmap_atomic_idx_pop();
    /* �ж������ַ�ռ��Ƿ���kmapռ�õĿռ� */
	} else if (vaddr >= PKMAP_ADDR(0) && vaddr < PKMAP_ADDR(LAST_PKMAP)) {
		/* this address was obtained through kmap_high_get() */
        /* �����kmap�ĵ�ַ�ռ䣬�������Ӧ������kunmap������ʵ��һ���ݴ���*/
		kunmap_high(pte_page(pkmap_page_table[PKMAP_NR(vaddr)]));
	}
    /**
     * ����ռ����kmap_atomic�����йر�����ռ������򿪡� 
     * ���仰˵����kmap_atomic��kunmap_atomic֮�䣬���ǹ���ռ�ġ�
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
