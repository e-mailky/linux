/*
 *	linux/kernel/softirq.c
 *
 *	Copyright (C) 1992 Linus Torvalds
 *
 *	Distribute under GPLv2.
 *
 *	Rewritten. Old one was good in 2.2, but in 2.3 it was immoral. --ANK (990903)
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/export.h>
#include <linux/kernel_stat.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/notifier.h>
#include <linux/percpu.h>
#include <linux/cpu.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/rcupdate.h>
#include <linux/ftrace.h>
#include <linux/smp.h>
#include <linux/smpboot.h>
#include <linux/tick.h>

#define CREATE_TRACE_POINTS
#include <trace/events/irq.h>

/*
   - No shared variables, all the data are CPU local.
   - If a softirq needs serialization, let it serialize itself
     by its own spinlocks.
   - Even if softirq is serialized, only local cpu is marked for
     execution. Hence, we get something sort of weak cpu binding.
     Though it is still not clear, will it result in better locality
     or will not.

   Examples:
   - NET RX softirq. It is multithreaded and does not require
     any global serialization.
   - NET TX softirq. It kicks software netdevice queues, hence
     it is logically serialized per device, but this serialization
     is invisible to common code.
   - Tasklets: serialized wrt itself.
 */

#ifndef __ARCH_IRQ_STAT
irq_cpustat_t irq_stat[NR_CPUS] ____cacheline_aligned;
EXPORT_SYMBOL(irq_stat);
#endif

static struct softirq_action softirq_vec[NR_SOFTIRQS] __cacheline_aligned_in_smp;

DEFINE_PER_CPU(struct task_struct *, ksoftirqd);

const char * const softirq_to_name[NR_SOFTIRQS] = {
	"HI", "TIMER", "NET_TX", "NET_RX", "BLOCK", "BLOCK_IOPOLL",
	"TASKLET", "SCHED", "HRTIMER", "RCU"
};

/*
 * we cannot loop indefinitely here to avoid userspace starvation,
 * but we also don't want to introduce a worst case 1/HZ latency
 * to the pending events, so lets the scheduler to balance
 * the softirq load for us.
 */
static void wakeup_softirqd(void)
{
	/* Interrupts are disabled: no need to stop preemption */
	struct task_struct *tsk = __this_cpu_read(ksoftirqd);

	if (tsk && tsk->state != TASK_RUNNING)
		wake_up_process(tsk);
}

/*
 * preempt_count and SOFTIRQ_OFFSET usage:
 * - preempt_count is changed by SOFTIRQ_OFFSET on entering or leaving
 *   softirq processing.
 * - preempt_count is changed by SOFTIRQ_DISABLE_OFFSET (= 2 * SOFTIRQ_OFFSET)
 *   on local_bh_disable or local_bh_enable.
 * This lets us distinguish between whether we are currently processing
 * softirq and whether we just have bh disabled.
 */

/*
 * This one is for softirq.c-internal use,
 * where hardirqs are disabled legitimately:
 */
#ifdef CONFIG_TRACE_IRQFLAGS
void __local_bh_disable_ip(unsigned long ip, unsigned int cnt)
{
	unsigned long flags;

	WARN_ON_ONCE(in_irq());

	raw_local_irq_save(flags);
	/*
	 * The preempt tracer hooks into preempt_count_add and will break
	 * lockdep because it calls back into lockdep after SOFTIRQ_OFFSET
	 * is set and before current->softirq_enabled is cleared.
	 * We must manually increment preempt_count here and manually
	 * call the trace_preempt_off later.
	 */
	__preempt_count_add(cnt);
	/*
	 * Were softirqs turned off above:
	 */
	if (softirq_count() == (cnt & SOFTIRQ_MASK))
		trace_softirqs_off(ip);
	raw_local_irq_restore(flags);

	if (preempt_count() == cnt)
		trace_preempt_off(CALLER_ADDR0, get_parent_ip(CALLER_ADDR1));
}
EXPORT_SYMBOL(__local_bh_disable_ip);
#endif /* CONFIG_TRACE_IRQFLAGS */

static void __local_bh_enable(unsigned int cnt)
{
	WARN_ON_ONCE(!irqs_disabled());

	if (softirq_count() == (cnt & SOFTIRQ_MASK))
		trace_softirqs_on(_RET_IP_);
	preempt_count_sub(cnt);
}

/*
 * Special-case - softirqs can safely be enabled in
 * cond_resched_softirq(), or by __do_softirq(),
 * without processing still-pending softirqs:
 */
void _local_bh_enable(void)
{
	WARN_ON_ONCE(in_irq());
	__local_bh_enable(SOFTIRQ_DISABLE_OFFSET);
}
EXPORT_SYMBOL(_local_bh_enable);

void __local_bh_enable_ip(unsigned long ip, unsigned int cnt)
{
    /*
     * 在中斷上下文，是不需要禁止和打開軟中斷的。
     * 在中斷被禁止時，也不需要禁止和打開軟中斷。
     * 這兩種情況下，都給出警告，可能是用法錯誤
     */
	WARN_ON_ONCE(in_irq() || irqs_disabled());
#ifdef CONFIG_TRACE_IRQFLAGS
	local_irq_disable();
#endif
	/*
	 * Are softirqs going to be turned on now:
	 */
	if (softirq_count() == SOFTIRQ_DISABLE_OFFSET)
		trace_softirqs_on(ip);
	/*
	 * Keep preemption disabled until we are done with
	 * softirq processing:
	 */
	preempt_count_sub(cnt - 1);

    /* 不在中斷，也不在軟中斷上下文，並且有掛起的中斷，才處理掛起的軟中斷。
     * 注意，此時的執行上下文是在線程上下文，中斷是打開的，因此調用do_softirq而不是__do_softirq
     */
	if (unlikely(!in_interrupt() && local_softirq_pending())) {
		/*
		 * Run softirq if any pending. And do it in its own stack
		 * as we may be calling this deep in a task call stack already.
		 */
		do_softirq();
	}

    /*
     * 由於打開了CONFIG_TRACE_IRQFLAGS時，此時處於關中斷狀態。打開搶佔不能進行搶佔調度。
     * 因此，此時先減少搶佔計數，待中斷打開後再判斷是否需要處理搶佔
     */
	preempt_count_dec();
#ifdef CONFIG_TRACE_IRQFLAGS
	local_irq_enable();
#endif
	preempt_check_resched();
}
EXPORT_SYMBOL(__local_bh_enable_ip);

/*
 * We restart softirq processing for at most MAX_SOFTIRQ_RESTART times,
 * but break the loop if need_resched() is set or after 2 ms.
 * The MAX_SOFTIRQ_TIME provides a nice upper bound in most cases, but in
 * certain cases, such as stop_machine(), jiffies may cease to
 * increment and so we need the MAX_SOFTIRQ_RESTART limit as
 * well to make sure we eventually return from this method.
 *
 * These limits have been established via experimentation.
 * The two things to balance is latency against fairness -
 * we want to handle softirqs as soon as possible, but they
 * should not be able to lock up the box.
 */
#define MAX_SOFTIRQ_TIME  msecs_to_jiffies(2)
#define MAX_SOFTIRQ_RESTART 10

#ifdef CONFIG_TRACE_IRQFLAGS
/*
 * When we run softirqs from irq_exit() and thus on the hardirq stack we need
 * to keep the lockdep irq context tracking as tight as possible in order to
 * not miss-qualify lock contexts and miss possible deadlocks.
 */

static inline bool lockdep_softirq_start(void)
{
	bool in_hardirq = false;

	if (trace_hardirq_context(current)) {
		in_hardirq = true;
		trace_hardirq_exit();
	}

	lockdep_softirq_enter();

	return in_hardirq;
}

static inline void lockdep_softirq_end(bool in_hardirq)
{
	lockdep_softirq_exit();

	if (in_hardirq)
		trace_hardirq_enter();
}
#else
static inline bool lockdep_softirq_start(void) { return false; }
static inline void lockdep_softirq_end(bool in_hardirq) { }
#endif

asmlinkage void __do_softirq(void)
{
    /*
     * 在一次調用__do_softirq的過程中，最多循環處理2ms(10次)的軟中斷。
     * 這樣做的目的是為了避免軟中斷大量佔用CPU，導致應用程序被餓死。
     * 實際上，這樣做達不到目的。要完全避免餓死應用程序，還是需要軟中斷線程化。
     * 當然，這裡的判斷應當是歷史原因。	int max_restart = MAX_SOFTIRQ_RESTART;
     */
	unsigned long end = jiffies + MAX_SOFTIRQ_TIME;
	unsigned long old_flags = current->flags;
	int max_restart = MAX_SOFTIRQ_RESTART;
	struct softirq_action *h;
	bool in_hardirq;
	__u32 pending;
	int softirq_bit;
	int cpu;

	/*
	 * Mask out PF_MEMALLOC s current task context is borrowed for the
	 * softirq. A softirq handled such as network RX might set PF_MEMALLOC
	 * again if the socket is related to swap
	 */
	current->flags &= ~PF_MEMALLOC;

    // 得到當前掛起軟中斷掩碼。注意當前仍然是關中斷狀態，可以安全的獲得掩碼。
	pending = local_softirq_pending();
	account_irq_enter_time(current);

    //屏蔽其他软中断，所以软中断仅仅能一个在执行。發生中斷後不會再重入本函數
	__local_bh_disable_ip(_RET_IP_, SOFTIRQ_OFFSET);
	in_hardirq = lockdep_softirq_start();

	cpu = smp_processor_id();
restart:
	/* Reset the pending bitmask before enabling irqs */
    // 每次循环在允许硬件 ISR 强占前，首先重置软中断的标志位。
	set_softirq_pending(0);

	local_irq_enable();

    /*
     * 这里要注意，以下代码运行时可以被硬件中断抢占，但这个硬件 ISR 执行完成后，
     * 它的所注册的软中断无法马上运行，别忘了，现在虽是开硬件中断执行，但前面的
     * __local_bh_disable()函数屏蔽了软中断。所以这种环境下只能被硬件中断抢占，
     * 但这个硬中断注册的软中断回调函数无法运行。要问为什么，那是因为__local_bh_disable()
     * 函数设置了一个标志当作互斥量，而这个标志正是上面的 irq_exit() 和 do_softirq()
     * 函数中的in_interrupt() 函数判断的条件之一，也就是说 in_interrupt()函数
     * 不仅检测硬中断而且还判断了软中断。所以在这个环境下触发硬中断时注册的软中断，
     * 根本无法重新进入到这个函数中来，只能是做一个标志，等待下面的重复循环
     *（最大 MAX_SOFTIRQ_RESTART）才可能处理到这个时候触发的硬件中断所注册的软中断。
     */
	h = softirq_vec;    // 得到软中断向量表

    // 循环处理所有 softirq 软中断注册函数。
	while ((softirq_bit = ffs(pending))) { //如果对应的软中断设置 pending 标志则表明需要进一步处理它所注册的函数
		unsigned int vec_nr;
		int prev_count;

		h += softirq_bit - 1;

		vec_nr = h - softirq_vec;
        // 在調用軟中斷處理函數前，保存搶佔計數。避免軟中斷函數破壞計數。
		prev_count = preempt_count();

		kstat_incr_softirqs_this_cpu(vec_nr);

		trace_softirq_entry(vec_nr);
        // 在这里执行了这个软中断所注册的回调函数
		h->action(h);
		trace_softirq_exit(vec_nr);
		/*
        * 軟中斷回調函數破壞了搶佔計數。這裡打印最高級別的警告
        * 並恢復正確的搶佔計數
        */
        if (unlikely(prev_count != preempt_count())) {
			pr_err("huh, entered softirq %u %s %p with preempt_count %08x, exited with %08x?\n",
			       vec_nr, softirq_to_name[vec_nr], h->action,
			       prev_count, preempt_count());
			preempt_count_set(prev_count);
		}
        /* 這裡是處理下半部分RCU靜止狀態 */
		rcu_bh_qs(cpu);
		h++;
		pending >>= softirq_bit;
	}

    /*
     * 关中断执行以下代码。注意：这里又关中断了，下面的代码执行过程中硬件中断无法抢占。
     * 前面提到过，在刚才开硬件中断执行环境时只能被硬件中断抢占，在这个时候是
     * 无法处理软中断的，因为刚才开中断执行过程中可能多次被硬件中断抢占，
     * 每抢占一次就有可能注册一个软中断，所以要再重新取一次所有的软中断。
     * 以便下面的代码进行处理后跳回到 restart 处重复执行。
     */
	local_irq_disable();

    /*
     * 如果在上面的开中断执行环境中触发了硬件中断，且每个都注册了一个软中断的话，
     * 这个软中断会设置 pending 位,但在当前一直屏蔽软中断的环境下无法得到执行，
     * 前面提到过，因为 irq_exit() 和 do_softirq() 根本无法进入到这个处理过程中来。
     * 这个在上面详细的记录过了。那么在这里又有了一个执行的机会。
     * 注意：虽然当前环境一直是处于屏蔽软中断执行的环境中，但在这里又给出了
     * 一个执行刚才在开中断环境过程中触发硬件中断时所注册的软中断的机会，
     * 其实只要理解了软中断机制就会知道，无非是在一些特定环境下调用 ISR 注册到
     * 软中断向量表里的函数而已。如果刚才触发的硬件中断注册了软中断，并且重复执行
     * 次数没有到 10 次的话，那么则跳转到 restart 标志处重复以上所介绍的所有步骤：
     * 设置软中断标志位，重新开中断执行...
     * 注意：这里是要两个条件都满足的情况下才可能重复以上步骤。
     */
	pending = local_softirq_pending();
	if (pending) {
		if (time_before(jiffies, end) && !need_resched() &&
		    --max_restart)
			goto restart;

        /*
         * 如果以上步骤重复了 10 次后还有 pending 的软中断的话，那么系统在一定时间内
         * 可能达到了一个峰值，为了平衡这点。系统专门建立了一个 ksoftirqd 线程来处理，
         * 这样避免在一定时间内负荷太大。这个 ksoftirqd 线程本身是一个大循环，
         * 在某些条件下为了不负载过重，它是可以被其他进程抢占的，但注意，它是显示的调用了
         * preempt_xxx() 和 schedule()才会被抢占和切换的。这么做的原因是因为在它一旦调用
         * local_softirq_pending() 函数检测到有 pending 的软中断需要处理的时候，
         * 则会显示的调用 do_softirq() 来处理软中断。也就是说，下面代码唤醒的 ksoftirqd
         * 线程有可能会回到这个函数当中来，尤其是在系统需要响应很多软中断的情况下，
         * 它的调用入口是 do_softirq()，这也就是为什么在 do_softirq()的入口处也会用
         * in_interrupt()函数来判断是否有软中断正在处理的原因了，目的还是为了防止重入。
         * ksoftirqd 实现看下面对 ksoftirqd() 函数的分析。
         */
        // 此函数实际是调用 wake_up_process() 来唤醒 ksoftirqd
		wakeup_softirqd();
	}

	lockdep_softirq_end(in_hardirq);
	account_irq_exit_time(current);
    /*
     * 到最后才开软中断执行环境，允许软中断执行。注意：这里 使用的不是
     * local_bh_enable()，不会再次触发 do_softirq()的调用。
     */
	__local_bh_enable(SOFTIRQ_OFFSET);
	WARN_ON_ONCE(in_interrupt());
	tsk_restore_flags(current, old_flags, PF_MEMALLOC);
}

asmlinkage void do_softirq(void)
{
	__u32 pending;
	unsigned long flags;

    /*
     * 这个函数判断，如果当前有硬件中断嵌套，或者有软中断正在执行时候，
     * 则马上返回。在这个入口判断主要是为了与 ksoftirqd 互斥。
     */
	if (in_interrupt())
		return;

    // 关中断执行以下代码
	local_irq_save(flags);

    //判断是否有softirq pending
	pending = local_softirq_pending();

	if (pending)
		do_softirq_own_stack();

	local_irq_restore(flags);
}

/*
 * Enter an interrupt context.
 */
void irq_enter(void)
{
	rcu_irq_enter();
	if (is_idle_task(current) && !in_interrupt()) {
		/*
		 * Prevent raise_softirq from needlessly waking up ksoftirqd
		 * here, as softirq will be serviced on return from interrupt.
		 */
		local_bh_disable();
		tick_irq_enter();
		_local_bh_enable();
	}

	__irq_enter();
}

static inline void invoke_softirq(void)
{
	if (!force_irqthreads) { /*沒有強制進行中斷線程化*/
#ifdef CONFIG_HAVE_IRQ_EXIT_ON_IRQ_STACK
		/*
		 * We can safely execute softirq on the current stack if
		 * it is the irq stack, because it should be near empty
		 * at this stage.
		 */
		__do_softirq();
#else
		/*
		 * Otherwise, irq_exit() is called on the task stack that can
		 * be potentially deep already. So call softirq in its own stack
		 * to prevent from any overrun.
		 */
		do_softirq_own_stack();
#endif
	} else { /* 中斷線程化了，軟中斷統一在線程上下文處理 */
		wakeup_softirqd();// 喚醒本CPU上的softirqd守護線程。由該線程處理掛起的軟中斷。
	}
}

static inline void tick_irq_exit(void)
{
#ifdef CONFIG_NO_HZ_COMMON
	int cpu = smp_processor_id();

	/* Make sure that timer wheel updates are propagated */
	if ((idle_cpu(cpu) && !need_resched()) || tick_nohz_full_cpu(cpu)) {
		if (!in_interrupt())
			tick_nohz_irq_exit();
	}
#endif
}

/*
 * Exit an interrupt context. Process softirqs if needed and possible:
 */
void irq_exit(void)
{
#ifndef __ARCH_IRQ_EXIT_IRQS_DISABLED
	local_irq_disable();
#else
	WARN_ON_ONCE(!irqs_disabled());
#endif

	account_irq_exit_time(current);
	preempt_count_sub(HARDIRQ_OFFSET);
	if (!in_interrupt() && local_softirq_pending())
		invoke_softirq();

	tick_irq_exit();
	rcu_irq_exit(); /* 在汇编中判断是否需要调度 */
	trace_hardirq_exit(); /* must be last! */
}

/*
 * This function must run with irqs disabled!
 */
inline void raise_softirq_irqoff(unsigned int nr)
{
	__raise_softirq_irqoff(nr);

	/*
	 * If we're in an interrupt or softirq, we're done
	 * (this also catches softirq-disabled code). We will
	 * actually run the softirq once we return from
	 * the irq or softirq.
	 *
	 * Otherwise we wake up ksoftirqd to make sure we
	 * schedule the softirq soon.
	 */
	if (!in_interrupt())
		wakeup_softirqd();
}

void raise_softirq(unsigned int nr)
{
	unsigned long flags;

	local_irq_save(flags);
	raise_softirq_irqoff(nr);
	local_irq_restore(flags);
}

void __raise_softirq_irqoff(unsigned int nr)
{
	trace_softirq_raise(nr);
	or_softirq_pending(1UL << nr);
}

void open_softirq(int nr, void (*action)(struct softirq_action *))
{
	softirq_vec[nr].action = action;
}

/*
 * Tasklets
 */
struct tasklet_head {
	struct tasklet_struct *head;
	struct tasklet_struct **tail;
};

static DEFINE_PER_CPU(struct tasklet_head, tasklet_vec);
static DEFINE_PER_CPU(struct tasklet_head, tasklet_hi_vec);

void __tasklet_schedule(struct tasklet_struct *t)
{
	unsigned long flags;

    // 禁止中斷，這樣可以避免與軟中斷衝突
	local_irq_save(flags);
	t->next = NULL;
	*__this_cpu_read(tasklet_vec.tail) = t;
	__this_cpu_write(tasklet_vec.tail, &(t->next));
	raise_softirq_irqoff(TASKLET_SOFTIRQ);
	local_irq_restore(flags);
}
EXPORT_SYMBOL(__tasklet_schedule);

void __tasklet_hi_schedule(struct tasklet_struct *t)
{
	unsigned long flags;

	local_irq_save(flags);
	t->next = NULL;
	*__this_cpu_read(tasklet_hi_vec.tail) = t;
	__this_cpu_write(tasklet_hi_vec.tail,  &(t->next));
	raise_softirq_irqoff(HI_SOFTIRQ);
	local_irq_restore(flags);
}
EXPORT_SYMBOL(__tasklet_hi_schedule);

void __tasklet_hi_schedule_first(struct tasklet_struct *t)
{
	BUG_ON(!irqs_disabled());

	t->next = __this_cpu_read(tasklet_hi_vec.head);
	__this_cpu_write(tasklet_hi_vec.head, t);
	__raise_softirq_irqoff(HI_SOFTIRQ);
}
EXPORT_SYMBOL(__tasklet_hi_schedule_first);

static void tasklet_action(struct softirq_action *a)
{
	struct tasklet_struct *list;

    //由於中斷可能註冊tasklet，因此，在獲取待處理的tasklet鏈表時，需要關閉中斷。
	local_irq_disable();
    //把tasklet_vec[n]（n为cpu号）指向的链表的地址存入局部变量list
	list = __this_cpu_read(tasklet_vec.head);
    //把tasklet_vec[n]（n为cpu号）的值设定为NULL，因此已经调度的tasklet描述符的链表被清空。
	__this_cpu_write(tasklet_vec.head, NULL);
	__this_cpu_write(tasklet_vec.tail, &__get_cpu_var(tasklet_vec).head);
	local_irq_enable();

	while (list) {
		struct tasklet_struct *t = list;

		list = list->next;

        /* 其他核上的中斷可能會調度一個tasklet開始運行。因此這裡試圖獲得它的鎖再執行其他回調
         * 查看count字段，检查tasklet是否被禁止，如果是，就清 TASKLET_STATE_SCHED
         * 同时执行tasklet函数
         */
		if (tasklet_trylock(t)) {
			if (!atomic_read(&t->count)) {/* 沒有禁止該tasklet */
                /* 任務沒有被禁止，又沒有被調度，但是又在鏈表中，是不正常的 */
				if (!test_and_clear_bit(TASKLET_STATE_SCHED,
							&t->state))
					BUG();
				t->func(t->data);
				tasklet_unlock(t);
				continue;
			}
			tasklet_unlock(t);
		}

        /*
         * 運行到里，說明不能獲得任務鎖，或者其他核在操作任務，
         * 因此需要將任務放回鏈表。在放回前，需要關中斷以保護鏈表。
         */
        local_irq_disable();
		t->next = NULL;
		*__this_cpu_read(tasklet_vec.tail) = t;
		__this_cpu_write(tasklet_vec.tail, &(t->next));
        /* 觸發TASKLET_SOFTIRQ，這樣，在do_softirq的下一輪將會處理該任務 */
		__raise_softirq_irqoff(TASKLET_SOFTIRQ);
		local_irq_enable();
	}
}

static void tasklet_hi_action(struct softirq_action *a)
{
	struct tasklet_struct *list;

	local_irq_disable();
	list = __this_cpu_read(tasklet_hi_vec.head);
	__this_cpu_write(tasklet_hi_vec.head, NULL);
	__this_cpu_write(tasklet_hi_vec.tail, &__get_cpu_var(tasklet_hi_vec).head);
	local_irq_enable();

	while (list) {
		struct tasklet_struct *t = list;

		list = list->next;

		if (tasklet_trylock(t)) {
			if (!atomic_read(&t->count)) {
				if (!test_and_clear_bit(TASKLET_STATE_SCHED,
							&t->state))
					BUG();
				t->func(t->data);
				tasklet_unlock(t);
				continue;
			}
			tasklet_unlock(t);
		}

		local_irq_disable();
		t->next = NULL;
		*__this_cpu_read(tasklet_hi_vec.tail) = t;
		__this_cpu_write(tasklet_hi_vec.tail, &(t->next));
		__raise_softirq_irqoff(HI_SOFTIRQ);
		local_irq_enable();
	}
}

void tasklet_init(struct tasklet_struct *t,
		  void (*func)(unsigned long), unsigned long data)
{
	t->next = NULL;
	t->state = 0;
	atomic_set(&t->count, 0);
	t->func = func;
	t->data = data;
}
EXPORT_SYMBOL(tasklet_init);

void tasklet_kill(struct tasklet_struct *t)
{
	if (in_interrupt())
		pr_notice("Attempt to kill tasklet from interrupt\n");

	while (test_and_set_bit(TASKLET_STATE_SCHED, &t->state)) {
		do {
			yield();
		} while (test_bit(TASKLET_STATE_SCHED, &t->state));
	}
	tasklet_unlock_wait(t);
	clear_bit(TASKLET_STATE_SCHED, &t->state);
}
EXPORT_SYMBOL(tasklet_kill);

/*
 * tasklet_hrtimer
 */

/*
 * The trampoline is called when the hrtimer expires. It schedules a tasklet
 * to run __tasklet_hrtimer_trampoline() which in turn will call the intended
 * hrtimer callback, but from softirq context.
 */
static enum hrtimer_restart __hrtimer_tasklet_trampoline(struct hrtimer *timer)
{
	struct tasklet_hrtimer *ttimer =
		container_of(timer, struct tasklet_hrtimer, timer);

	tasklet_hi_schedule(&ttimer->tasklet);
	return HRTIMER_NORESTART;
}

/*
 * Helper function which calls the hrtimer callback from
 * tasklet/softirq context
 */
static void __tasklet_hrtimer_trampoline(unsigned long data)
{
	struct tasklet_hrtimer *ttimer = (void *)data;
	enum hrtimer_restart restart;

	restart = ttimer->function(&ttimer->timer);
	if (restart != HRTIMER_NORESTART)
		hrtimer_restart(&ttimer->timer);
}

/**
 * tasklet_hrtimer_init - Init a tasklet/hrtimer combo for softirq callbacks
 * @ttimer:	 tasklet_hrtimer which is initialized
 * @function:	 hrtimer callback function which gets called from softirq context
 * @which_clock: clock id (CLOCK_MONOTONIC/CLOCK_REALTIME)
 * @mode:	 hrtimer mode (HRTIMER_MODE_ABS/HRTIMER_MODE_REL)
 */
void tasklet_hrtimer_init(struct tasklet_hrtimer *ttimer,
			  enum hrtimer_restart (*function)(struct hrtimer *),
			  clockid_t which_clock, enum hrtimer_mode mode)
{
	hrtimer_init(&ttimer->timer, which_clock, mode);
	ttimer->timer.function = __hrtimer_tasklet_trampoline;
	tasklet_init(&ttimer->tasklet, __tasklet_hrtimer_trampoline,
		     (unsigned long)ttimer);
	ttimer->function = function;
}
EXPORT_SYMBOL_GPL(tasklet_hrtimer_init);

void __init softirq_init(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		per_cpu(tasklet_vec, cpu).tail =
			&per_cpu(tasklet_vec, cpu).head;
		per_cpu(tasklet_hi_vec, cpu).tail =
			&per_cpu(tasklet_hi_vec, cpu).head;
	}

	open_softirq(TASKLET_SOFTIRQ, tasklet_action);
	open_softirq(HI_SOFTIRQ, tasklet_hi_action);
}

static int ksoftirqd_should_run(unsigned int cpu)
{
	return local_softirq_pending();
}

static void run_ksoftirqd(unsigned int cpu)
{
	local_irq_disable();
	if (local_softirq_pending()) {
		/*
		 * We can safely run softirq on inline stack, as we are not deep
		 * in the task stack here.
		 */
		__do_softirq();
		rcu_note_context_switch(cpu);
		local_irq_enable();
		cond_resched();
		return;
	}
	local_irq_enable();
}

#ifdef CONFIG_HOTPLUG_CPU
/*
 * tasklet_kill_immediate is called to remove a tasklet which can already be
 * scheduled for execution on @cpu.
 *
 * Unlike tasklet_kill, this function removes the tasklet
 * _immediately_, even if the tasklet is in TASKLET_STATE_SCHED state.
 *
 * When this function is called, @cpu must be in the CPU_DEAD state.
 */
void tasklet_kill_immediate(struct tasklet_struct *t, unsigned int cpu)
{
	struct tasklet_struct **i;

	BUG_ON(cpu_online(cpu));
	BUG_ON(test_bit(TASKLET_STATE_RUN, &t->state));

	if (!test_bit(TASKLET_STATE_SCHED, &t->state))
		return;

	/* CPU is dead, so no lock needed. */
	for (i = &per_cpu(tasklet_vec, cpu).head; *i; i = &(*i)->next) {
		if (*i == t) {
			*i = t->next;
			/* If this was the tail element, move the tail ptr */
			if (*i == NULL)
				per_cpu(tasklet_vec, cpu).tail = i;
			return;
		}
	}
	BUG();
}

static void takeover_tasklets(unsigned int cpu)
{
	/* CPU is dead, so no lock needed. */
	local_irq_disable();

	/* Find end, append list for that CPU. */
	if (&per_cpu(tasklet_vec, cpu).head != per_cpu(tasklet_vec, cpu).tail) {
		*__this_cpu_read(tasklet_vec.tail) = per_cpu(tasklet_vec, cpu).head;
		this_cpu_write(tasklet_vec.tail, per_cpu(tasklet_vec, cpu).tail);
		per_cpu(tasklet_vec, cpu).head = NULL;
		per_cpu(tasklet_vec, cpu).tail = &per_cpu(tasklet_vec, cpu).head;
	}
	raise_softirq_irqoff(TASKLET_SOFTIRQ);

	if (&per_cpu(tasklet_hi_vec, cpu).head != per_cpu(tasklet_hi_vec, cpu).tail) {
		*__this_cpu_read(tasklet_hi_vec.tail) = per_cpu(tasklet_hi_vec, cpu).head;
		__this_cpu_write(tasklet_hi_vec.tail, per_cpu(tasklet_hi_vec, cpu).tail);
		per_cpu(tasklet_hi_vec, cpu).head = NULL;
		per_cpu(tasklet_hi_vec, cpu).tail = &per_cpu(tasklet_hi_vec, cpu).head;
	}
	raise_softirq_irqoff(HI_SOFTIRQ);

	local_irq_enable();
}
#endif /* CONFIG_HOTPLUG_CPU */

static int cpu_callback(struct notifier_block *nfb, unsigned long action,
			void *hcpu)
{
	switch (action) {
#ifdef CONFIG_HOTPLUG_CPU
	case CPU_DEAD:
	case CPU_DEAD_FROZEN:
		takeover_tasklets((unsigned long)hcpu);
		break;
#endif /* CONFIG_HOTPLUG_CPU */
	}
	return NOTIFY_OK;
}

static struct notifier_block cpu_nfb = {
	.notifier_call = cpu_callback
};

static struct smp_hotplug_thread softirq_threads = {
	.store			= &ksoftirqd,
	.thread_should_run	= ksoftirqd_should_run,
	.thread_fn		= run_ksoftirqd,
	.thread_comm		= "ksoftirqd/%u",
};

static __init int spawn_ksoftirqd(void)
{
	register_cpu_notifier(&cpu_nfb);

	BUG_ON(smpboot_register_percpu_thread(&softirq_threads));

	return 0;
}
early_initcall(spawn_ksoftirqd);

/*
 * [ These __weak aliases are kept in a separate compilation unit, so that
 *   GCC does not inline them incorrectly. ]
 */

int __init __weak early_irq_init(void)
{
	return 0;
}

int __init __weak arch_probe_nr_irqs(void)
{
	return NR_IRQS_LEGACY;
}

int __init __weak arch_early_irq_init(void)
{
	return 0;
}
