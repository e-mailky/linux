#ifndef _LINUX_SLAB_DEF_H
#define	_LINUX_SLAB_DEF_H

#include <linux/reciprocal_div.h>

/*
 * Definitions unique to the original Linux SLAB allocator.
*/

/* cache, slab, page的关系可大致表示如下 
 *                                                  |->object
                       |-->slab_full---->slab->page-+-> ...
                       |                            |->object
                       |                            |->object
kmem_cache->kmem_list3->slab_partial-->slab->page---+-> ...
                       |                            |->object
                       |                            |->object
                       |-->slab_free---->slab->page-+-> ...
                       |                            |->object
*/

struct kmem_cache {
    /*
     * 要转移进本地高速缓存或从本地高速缓存中转移出的大批对象的数量。
     * 当每CPU缓存的数量不足或者过多时，向本地缓存中一次移入batchcount个内存对象。
     */
/* 1) Cache tunables. Protected by slab_mutex */
	unsigned int batchcount;
	unsigned int limit; /* 本地高速缓存中空闲对象的最大数目。超过此值时，从本地缓存中归还batchcount个对象 */
	unsigned int shared;

	unsigned int size; /* 每一个分配的内存区在slab中的大小 */
    /* 要计算每一个分配出去的内存区在slab中的索引，可以用该内存区在slab中的偏移位置及内存区大小进行除法运算而得到，使用本字段是为了避免除法运算 */
	struct reciprocal_value reciprocal_buffer_size;
/* 2) touched by every alloc & free from the backend */

	unsigned int flags;		/* constant flags 描述高速缓存属性的一组标志 */
	unsigned int num;		/* # of objs per slab 在一个单独slab中的包含的内存区的个数 */

/* 3) cache_grow/shrink */
	/* order of pgs per slab (2^n)  一个单独slab中包含的连续页框数目的对数 */
	unsigned int gfporder;

	/* force GFP flags, e.g. GFP_DMA 分配页框时传递给伙伴系统函数的一组标志 */
	gfp_t allocflags;

    /*
     * slab使用的颜色个数。为了避免缓存抖动，每个slab使用不同的着色。本字段表示所有slab可以颜色个数
     */
	size_t colour;			/* cache colouring range */
    /*
     * slab中的基本对齐偏移。如果没有特别指定，就是一个缓存行的大小。
     * 如果某个slab中计算的颜色值超过此值，则取其模作为该slab的颜色值
     */
	unsigned int colour_off;	/* colour offset */
	struct kmem_cache *freelist_cache;  /* 指向包含slab描述符的普通slab高速缓存。如果使用了内部slab描述符，则这个字段为NULL */
	unsigned int freelist_size;         /* 单个slab大小。只包含slab中管理数据区的大小。不含slab中的数据区域 */

	/* constructor func 构造方法，当分配一个内存区时回调此方法。可以在此进行一些数据初始化工作 */
	void (*ctor)(void *obj);

/* 4) cache creation/removal */
	const char *name;
	struct list_head list;/* 高速缓存链表。通过此结构将数据区链接到全局高速缓存链表中去 */
	int refcount;
	int object_size;
	int align;

/* 5) statistics */
#ifdef CONFIG_DEBUG_SLAB
	unsigned long num_active;
	unsigned long num_allocations;
	unsigned long high_mark;
	unsigned long grown;
	unsigned long reaped;
	unsigned long errors;
	unsigned long max_freeable;
	unsigned long node_allocs;
	unsigned long node_frees;
	unsigned long node_overflow;
	atomic_t allochit;
	atomic_t allocmiss;
	atomic_t freehit;
	atomic_t freemiss;

	/*
	 * If debugging is enabled, then the allocator can add additional
	 * fields and/or padding to every object. size contains the total
	 * object size including these internal fields, the following two
	 * variables contain the offset to the user object and its size.
	 */
	int obj_offset;
#endif /* CONFIG_DEBUG_SLAB */
#ifdef CONFIG_MEMCG_KMEM
	struct memcg_cache_params *memcg_params;
#endif

/* 6) per-cpu/per-node data, touched during every alloc/free */
	/*
	 * We put array[] at the end of kmem_cache, because we want to size
	 * this array to nr_cpu_ids slots instead of NR_CPUS
	 * (see kmem_cache_init())
	 * We still use [NR_CPUS] and not [1] or [0] because cache_cache
	 * is statically defined, so we reserve the max number of cpus.
	 *
	 * We also need to guarantee that the list is able to accomodate a
	 * pointer for each node since "nodelists" uses the remainder of
	 * available pointers.
	 */
    /* 记录每个NUMA节点上的空闲slab、部分空闲slab、完全使用的slab */
	struct kmem_cache_node **node;
    /*
     * 每CPU指针数组，指向包含空闲对象的本地高速缓存。
     * 在分配内存时，优先从本CPU缓存中分配。这样可以减少spinlock的使用
     */
	struct array_cache *array[NR_CPUS + MAX_NUMNODES];
	/*
	 * Do not add fields after array[]
	 */
};

#endif	/* _LINUX_SLAB_DEF_H */
