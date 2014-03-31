#ifndef _LINUX_SLAB_DEF_H
#define	_LINUX_SLAB_DEF_H

#include <linux/reciprocal_div.h>

/*
 * Definitions unique to the original Linux SLAB allocator.
*/

/* cache, slab, page�Ĺ�ϵ�ɴ��±�ʾ���� 
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
     * Ҫת�ƽ����ظ��ٻ����ӱ��ظ��ٻ�����ת�Ƴ��Ĵ��������������
     * ��ÿCPU���������������߹���ʱ���򱾵ػ�����һ������batchcount���ڴ����
     */
/* 1) Cache tunables. Protected by slab_mutex */
	unsigned int batchcount;
	unsigned int limit; /* ���ظ��ٻ����п��ж���������Ŀ��������ֵʱ���ӱ��ػ����й黹batchcount������ */
	unsigned int shared;

	unsigned int size; /* ÿһ��������ڴ�����slab�еĴ�С */
    /* Ҫ����ÿһ�������ȥ���ڴ�����slab�е������������ø��ڴ�����slab�е�ƫ��λ�ü��ڴ�����С���г���������õ���ʹ�ñ��ֶ���Ϊ�˱���������� */
	struct reciprocal_value reciprocal_buffer_size;
/* 2) touched by every alloc & free from the backend */

	unsigned int flags;		/* constant flags �������ٻ������Ե�һ���־ */
	unsigned int num;		/* # of objs per slab ��һ������slab�еİ������ڴ����ĸ��� */

/* 3) cache_grow/shrink */
	/* order of pgs per slab (2^n)  һ������slab�а���������ҳ����Ŀ�Ķ��� */
	unsigned int gfporder;

	/* force GFP flags, e.g. GFP_DMA ����ҳ��ʱ���ݸ����ϵͳ������һ���־ */
	gfp_t allocflags;

    /*
     * slabʹ�õ���ɫ������Ϊ�˱��⻺�涶����ÿ��slabʹ�ò�ͬ����ɫ�����ֶα�ʾ����slab������ɫ����
     */
	size_t colour;			/* cache colouring range */
    /*
     * slab�еĻ�������ƫ�ơ����û���ر�ָ��������һ�������еĴ�С��
     * ���ĳ��slab�м������ɫֵ������ֵ����ȡ��ģ��Ϊ��slab����ɫֵ
     */
	unsigned int colour_off;	/* colour offset */
	struct kmem_cache *freelist_cache;  /* ָ�����slab����������ͨslab���ٻ��档���ʹ�����ڲ�slab��������������ֶ�ΪNULL */
	unsigned int freelist_size;         /* ����slab��С��ֻ����slab�й����������Ĵ�С������slab�е��������� */

	/* constructor func ���췽����������һ���ڴ���ʱ�ص��˷����������ڴ˽���һЩ���ݳ�ʼ������ */
	void (*ctor)(void *obj);

/* 4) cache creation/removal */
	const char *name;
	struct list_head list;/* ���ٻ�������ͨ���˽ṹ�����������ӵ�ȫ�ָ��ٻ���������ȥ */
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
    /* ��¼ÿ��NUMA�ڵ��ϵĿ���slab�����ֿ���slab����ȫʹ�õ�slab */
	struct kmem_cache_node **node;
    /*
     * ÿCPUָ�����飬ָ��������ж���ı��ظ��ٻ��档
     * �ڷ����ڴ�ʱ�����ȴӱ�CPU�����з��䡣�������Լ���spinlock��ʹ��
     */
	struct array_cache *array[NR_CPUS + MAX_NUMNODES];
	/*
	 * Do not add fields after array[]
	 */
};

#endif	/* _LINUX_SLAB_DEF_H */
