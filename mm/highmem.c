/*
 * High memory handling common code and variables.
 *
 * (C) 1999 Andrea Arcangeli, SuSE GmbH, andrea@suse.de
 *          Gerhard Wichert, Siemens AG, Gerhard.Wichert@pdb.siemens.de
 *
 *
 * Redesigned the x86 32-bit VM architecture to deal with
 * 64-bit physical space. With current x86 CPUs this
 * means up to 64 Gigabytes physical RAM.
 *
 * Rewrote high memory support to move the page cache into
 * high memory. Implemented permanent (schedulable) kmaps
 * based on Linus' idea.
 *
 * Copyright (C) 1999 Ingo Molnar <mingo@redhat.com>
 */

#include <linux/mm.h>
#include <linux/export.h>
#include <linux/swap.h>
#include <linux/bio.h>
#include <linux/pagemap.h>
#include <linux/mempool.h>
#include <linux/blkdev.h>
#include <linux/init.h>
#include <linux/hash.h>
#include <linux/highmem.h>
#include <linux/kgdb.h>
#include <asm/tlbflush.h>


#if defined(CONFIG_HIGHMEM) || defined(CONFIG_X86_32)
DEFINE_PER_CPU(int, __kmap_atomic_idx);
#endif

/*
 * Virtual_count is not a pure "count".
 *  0 means that it is not mapped, and has not been mapped
 *    since a TLB flush - it is usable.
 *  1 means that there are no users, but it has been mapped
 *    since the last TLB flush - so we can't use it.
 *  n means that there are (n-1) current users of it.
 */
#ifdef CONFIG_HIGHMEM

unsigned long totalhigh_pages __read_mostly;
EXPORT_SYMBOL(totalhigh_pages);


EXPORT_PER_CPU_SYMBOL(__kmap_atomic_idx);

unsigned int nr_free_highpages (void)
{
	pg_data_t *pgdat;
	unsigned int pages = 0;

	for_each_online_pgdat(pgdat) {
		pages += zone_page_state(&pgdat->node_zones[ZONE_HIGHMEM],
			NR_FREE_PAGES);
		if (zone_movable_is_highmem())
			pages += zone_page_state(
					&pgdat->node_zones[ZONE_MOVABLE],
					NR_FREE_PAGES);
	}

	return pages;
}

static int pkmap_count[LAST_PKMAP];
static unsigned int last_pkmap_nr;
static  __cacheline_aligned_in_smp DEFINE_SPINLOCK(kmap_lock);

pte_t * pkmap_page_table;

static DECLARE_WAIT_QUEUE_HEAD(pkmap_map_wait);

/*
 * Most architectures have no use for kmap_high_get(), so let's abstract
 * the disabling of IRQ out of the locking in that case to save on a
 * potential useless overhead.
 */
#ifdef ARCH_NEEDS_KMAP_HIGH_GET
#define lock_kmap()             spin_lock_irq(&kmap_lock)
#define unlock_kmap()           spin_unlock_irq(&kmap_lock)
#define lock_kmap_any(flags)    spin_lock_irqsave(&kmap_lock, flags)
#define unlock_kmap_any(flags)  spin_unlock_irqrestore(&kmap_lock, flags)
#else
#define lock_kmap()             spin_lock(&kmap_lock)
#define unlock_kmap()           spin_unlock(&kmap_lock)
#define lock_kmap_any(flags)    \
		do { spin_lock(&kmap_lock); (void)(flags); } while (0)
#define unlock_kmap_any(flags)  \
		do { spin_unlock(&kmap_lock); (void)(flags); } while (0)
#endif

struct page *kmap_to_page(void *vaddr)
{
	unsigned long addr = (unsigned long)vaddr;

	if (addr >= PKMAP_ADDR(0) && addr < PKMAP_ADDR(LAST_PKMAP)) {
		int i = PKMAP_NR(addr);
		return pte_page(pkmap_page_table[i]);
	}

	return virt_to_page(addr);
}
EXPORT_SYMBOL(kmap_to_page);

static void flush_all_zero_pkmaps(void)
{
	int i;
	int need_flush = 0;

	flush_cache_kmaps();

	for (i = 0; i < LAST_PKMAP; i++) {
		struct page *page;

		/*
		 * zero means we don't have anything to do,
		 * >1 means that it is still in use. Only
		 * a count of 1 means that it is free but
		 * needs to be unmapped
		 */
		if (pkmap_count[i] != 1)
			continue;
		pkmap_count[i] = 0;

		/* sanity check */
		BUG_ON(pte_none(pkmap_page_table[i]));

		/*
		 * Don't need an atomic fetch-and-clear op here;
		 * no-one has the page mapped, and cannot get at
		 * its virtual address (and hence PTE) without first
		 * getting the kmap_lock (which is held here).
		 * So no dangers, even with speculative execution.
		 */
		page = pte_page(pkmap_page_table[i]);
		pte_clear(&init_mm, PKMAP_ADDR(i), &pkmap_page_table[i]);

		set_page_address(page, NULL);
		need_flush = 1;
	}
	if (need_flush)
		flush_tlb_kernel_range(PKMAP_ADDR(0), PKMAP_ADDR(LAST_PKMAP));
}

/**
 * kmap_flush_unused - flush all unused kmap mappings in order to remove stray mappings
 */
void kmap_flush_unused(void)
{
	lock_kmap();
	flush_all_zero_pkmaps();
	unlock_kmap();
}

/* 为建立永久内核映射建立初始映射 */
static inline unsigned long map_new_virtual(struct page *page)
{
	unsigned long vaddr;
	int count;

start:
    /**
     * 允许搜索的次数，由于我们在下面的循环中可能进行两次遍历，
     * 两次遍历的总比较次数应该是kmap虚拟地址空间总页面数量(512) 
     */
	count = LAST_PKMAP;
	/* Find an empty entry */
	for (;;) {/* 扫描pkmap_count中的所有计数器值,直到找到一个空值.空值表示该虚拟地址还没有被kmap占用 */
		last_pkmap_nr = (last_pkmap_nr + 1) & LAST_PKMAP_MASK;/* 从上次结束的地方开始搜索. */
        /**
         * 搜索到最后一位了.再从0开始搜索前,刷新计数为1的项.
         * 当计数值为1表示页表项可用,但是对应的TLB还没有刷新(没有失效，即其pte页表项还存在).
         */
		if (!last_pkmap_nr) {
			flush_all_zero_pkmaps();
			count = LAST_PKMAP;
		}
		if (!pkmap_count[last_pkmap_nr])//* 找到计数为0的页表项,表示该页空闲且可用
			break;	/* Found a usable entry */
        /**
         * count是允许的搜索次数.如果还允许继续搜索下一个页表项.
         * 则继续,否则表示搜索完所有kmap地址项，没有空闲项,退出
         */
		if (--count)
			continue;

		/*
		 * Sleep for somebody else to unmap their entries
         * 运行到这里,表示没有找到空闲页表项.先睡眠一下.
         * 等待其他线程释放页表项,然后唤醒本线程
		 */
		{
			DECLARE_WAITQUEUE(wait, current);

			__set_current_state(TASK_UNINTERRUPTIBLE);
            /* 将当前线程挂到pkmap_map_wait等待队列上 */
			add_wait_queue(&pkmap_map_wait, &wait);
			unlock_kmap(); /* 开始睡眠前，必须释放自旋锁 */
			schedule();
            /**
             * 再次调度回来，说明其他线程释放了kmap虚拟地址空间，唤醒了本线程，
             * 首先将自己从等待队列中摘除 
             */
			remove_wait_queue(&pkmap_map_wait, &wait);
			lock_kmap();  /* 重新获得kmap_lock自旋锁 */

            /**
             * 在当前线程等待的过程中,其他线程可能已经将页面进行了映射.
             * 检测一下,如果已经映射了,就退出.
             * 注意,这里没有对kmap_lock进行解锁操作.关于kmap_lock锁的操作,需要结合kmap_high来分析.
             * 总的原则是:进入本函数时保证关锁,然后在本句前面关锁,本句后面解锁.
             * 在函数返回后,锁仍然是关的.则外层解锁.
             * 即使在本函数中循环也是这样.
             * 内核就是这么让人感到迷糊,看久了就习惯了.不过你目前可能必须得学着适应这种代码.
             */      
            /* Somebody else might have mapped it while we slept */
			if (page_address(page))
				return (unsigned long)page_address(page);

			/* Re-start */
			goto start;
		}
	}
    /**
     * 不管何种路径运行到这里来,kmap_lock都是锁着的.
     * 并且last_pkmap_nr对应的是一个空闲且可用的表项.
     */
	vaddr = PKMAP_ADDR(last_pkmap_nr);
    /* 设置页表属性,建立虚拟地址和物理地址之间的映射 */
	set_pte_at(&init_mm, vaddr,
		   &(pkmap_page_table[last_pkmap_nr]), mk_pte(page, kmap_prot));

	pkmap_count[last_pkmap_nr] = 1;
    /* 1表示相应的项可用,但是TLB需要刷新.注意前面的set_pte_at仅仅是建立了页面项，硬件tlb还等待刷新 */
	set_page_address(page, (void *)vaddr);

	return vaddr;
}

/**
 * kmap_high - map a highmem page into memory
 * @page: &struct page to map
 *
 * Returns the page's virtual memory address.
 *
 * We cannot call this from interrupts, as it may block.
 * 为高端内存建立永久内核映射
 */
void *kmap_high(struct page *page)
{
	unsigned long vaddr;

	/*
	 * For highmem pages, we can't trust "virtual" until
	 * after we have the lock.
     * 获得kmap_lock自旋锁，这把锁有两个作用:
     *   1:确保只对page进行一次kmap映射，如果两个地方同时调用kmap映射页面，
     *      则只有一次kmap进行真正的映射。
     *   2:kmap需要分配一个可用内核虚拟地址，这里保护虚拟地址空间分配时用到的数据结构 
     */
	lock_kmap();
	vaddr = (unsigned long)page_address(page);/* 再次获取页面的虚拟地址 */
	if (!vaddr) /* 如果确实没有对该页面进行映射，则调用map_new_virtual获得一个可用的虚拟地址 */
		vaddr = map_new_virtual(page); /* 这里可能导致阻塞，因为虚拟地址空间可能不足，需要等待 */
    /* 将该虚拟地址对应的映射计数加1，如果多次映射，则直到最后一次kunmap调用完毕后才真正解除pte页表项 */
	pkmap_count[PKMAP_NR(vaddr)]++;
    /**
     * 初次映射时,map_new_virtual中会将计数置为1,上一句再加1.
     * 多次映射时,计数值会再加1.
     * 总之,计数值决不会小于2.
     */
    BUG_ON(pkmap_count[PKMAP_NR(vaddr)] < 2);
	unlock_kmap(); /* 释放kmap_lock自旋锁 */
	return (void*) vaddr;
}

EXPORT_SYMBOL(kmap_high);

#ifdef ARCH_NEEDS_KMAP_HIGH_GET
/**
 * kmap_high_get - pin a highmem page into memory
 * @page: &struct page to pin
 *
 * Returns the page's current virtual memory address, or NULL if no mapping
 * exists.  If and only if a non null address is returned then a
 * matching call to kunmap_high() is necessary.
 *
 * This can be called from any context.
 */
void *kmap_high_get(struct page *page)
{
	unsigned long vaddr, flags;

	lock_kmap_any(flags);
	vaddr = (unsigned long)page_address(page);
	if (vaddr) {
		BUG_ON(pkmap_count[PKMAP_NR(vaddr)] < 1);
		pkmap_count[PKMAP_NR(vaddr)]++;
	}
	unlock_kmap_any(flags);
	return (void*) vaddr;
}
#endif

/**
 * kunmap_high - unmap a highmem page into memory
 * @page: &struct page to unmap
 *
 * If ARCH_NEEDS_KMAP_HIGH_GET is not defined then this may be called
 * only from user context. 
 * 解除高端内存的永久内核映射
 */
void kunmap_high(struct page *page)
{
	unsigned long vaddr;
	unsigned long nr;
	unsigned long flags;
	int need_wakeup;

	lock_kmap_any(flags);   /* 获得kmap_lock自旋锁 */
	vaddr = (unsigned long)page_address(page); /* 得到物理页对应的虚拟地址。*/
	BUG_ON(!vaddr); /* vaddr==0，可能是内存越界等严重故障了吧。或者是误调用BUG一下*/
	nr = PKMAP_NR(vaddr);/* 根据虚拟地址，找到页表项在pkmap_count中的序号 */

	/*
	 * A count must never go down to zero
	 * without a TLB flush!
	 */
	need_wakeup = 0;
	switch (--pkmap_count[nr]) {/* 首先将该页面的映射计数减1 */
	case 0: /* 一定是逻辑错误了，多次调用了unmap */
		BUG();
	case 1: /* 1表示该虚拟地址已经没有任何人映射了，可被其他线程使用 */
		/*
		 * Avoid an unnecessary wake_up() function call.
		 * The common case is pkmap_count[] == 1, but
		 * no waiters.
		 * The tasks queued in the wait-queue are guarded
		 * by both the lock in the wait-queue-head and by
		 * the kmap_lock.  As the kmap_lock is held here,
		 * no need for the wait-queue-head's lock.  Simply
		 * test if the queue is empty.
         * 页表项可用了。need_wakeup会判断是否有等待唤醒。
         * 如果有线程在等待kmap虚拟地址空间的话。
		 */
		need_wakeup = waitqueue_active(&pkmap_map_wait);
	}
	unlock_kmap_any(flags);

	/* do wake-up, if needed, race-free outside of the spin lock */
	if (need_wakeup)
		wake_up(&pkmap_map_wait);
}

EXPORT_SYMBOL(kunmap_high);
#endif

#if defined(HASHED_PAGE_VIRTUAL)

#define PA_HASH_ORDER	7

/*
 * Describes one page->virtual association
 */
struct page_address_map {
	struct page *page;
	void *virtual;
	struct list_head list;
};

static struct page_address_map page_address_maps[LAST_PKMAP];

/*
 * Hash table bucket
 */
static struct page_address_slot {
	struct list_head lh;			/* List of page_address_maps */
	spinlock_t lock;			/* Protect this bucket's list */
} ____cacheline_aligned_in_smp page_address_htable[1<<PA_HASH_ORDER];

static struct page_address_slot *page_slot(const struct page *page)
{
	return &page_address_htable[hash_ptr(page, PA_HASH_ORDER)];
}

/**
 * page_address - get the mapped virtual address of a page
 * @page: &struct page to get the virtual address of
 *
 * Returns the page's virtual address.获得一个页面的内核虚拟地址
 */
void *page_address(const struct page *page)
{
	unsigned long flags;
	void *ret;
	struct page_address_slot *pas;

    /**
     * 如果不是高端内存，那么直接返回它的线性地址，因为内核可以直接访问这样的内存。
     * 当然，在arm\x86架构中，还是需要pte页表项才能访问线性地址。
     * 对powerpc和mips来说，访问线性地址的机制不太一样
     */	
    if (!PageHighMem(page))
		return lowmem_page_address(page);

    /**
     * 否则页框在高端内存中(PG_highmem标志为1)，则到page_address_htable散列表中查找。
     * 该哈希表记录了非线性性映射的所有页面。
     * 这里是查找页面所在的哈希桶
     */	
    pas = page_slot(page);
	ret = NULL;
	spin_lock_irqsave(&pas->lock, flags);/* 关中断并获得哈希桶链表的自旋锁 */
    /* 映射高端内存的情况毕竟是少数，哈希桶一般是空的，这里判断哈希桶是否为空 */
	if (!list_empty(&pas->lh)) {
		struct page_address_map *pam;

        /* 如果哈希桶不为空，则遍历其中的第一项 */
		list_for_each_entry(pam, &pas->lh, list) {
			if (pam->page == page) {/* 如果当前页面在桶中 */
				ret = pam->virtual; /* 取得该页面的内核虚拟地址，并返回 */
				goto done;
			}
		}
	}
    /* 没有在page_address_htable中找到，返回默认值NULL */
done:
	spin_unlock_irqrestore(&pas->lock, flags);
	return ret;
}

EXPORT_SYMBOL(page_address);

/**
 * set_page_address - set a page's virtual address
 * @page: &struct page to set
 * @virtual: virtual address to use
 */
void set_page_address(struct page *page, void *virtual)
{
	unsigned long flags;
	struct page_address_slot *pas;
	struct page_address_map *pam;

	BUG_ON(!PageHighMem(page));

	pas = page_slot(page);
	if (virtual) {		/* Add */
		pam = &page_address_maps[PKMAP_NR((unsigned long)virtual)];
		pam->page = page;
		pam->virtual = virtual;

		spin_lock_irqsave(&pas->lock, flags);
		list_add_tail(&pam->list, &pas->lh);
		spin_unlock_irqrestore(&pas->lock, flags);
	} else {		/* Remove */
		spin_lock_irqsave(&pas->lock, flags);
		list_for_each_entry(pam, &pas->lh, list) {
			if (pam->page == page) {
				list_del(&pam->list);
				spin_unlock_irqrestore(&pas->lock, flags);
				goto done;
			}
		}
		spin_unlock_irqrestore(&pas->lock, flags);
	}
done:
	return;
}

void __init page_address_init(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(page_address_htable); i++) {
		INIT_LIST_HEAD(&page_address_htable[i].lh);
		spin_lock_init(&page_address_htable[i].lock);
	}
}

#endif	/* defined(CONFIG_HIGHMEM) && !defined(WANT_PAGE_VIRTUAL) */
