// SPDX-License-Identifier: GPL-2.0
/*
 * Stack trace management functions
 *
 *  Copyright IBM Corp. 2006
 *  Author(s): Heiko Carstens <heiko.carstens@de.ibm.com>
 */

#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/stacktrace.h>
#include <linux/kallsyms.h>
#include <linux/export.h>
#include <asm/stacktrace.h>
#include <asm/unwind.h>

const char *stack_type_name(enum stack_type type)
{
	switch (type) {
	case STACK_TYPE_TASK:
		return "task";
	case STACK_TYPE_IRQ:
		return "irq";
	case STACK_TYPE_NODAT:
		return "nodat";
	case STACK_TYPE_RESTART:
		return "restart";
	default:
		return "unknown";
	}
}

static inline bool in_stack(unsigned long sp, struct stack_info *info,
			    enum stack_type type, unsigned long low,
			    unsigned long high)
{
	if (sp < low || sp >= high)
		return false;
	info->type = type;
	info->begin = low;
	info->end = high;
	return true;
}

static bool in_task_stack(unsigned long sp, struct task_struct *task,
			  struct stack_info *info)
{
	unsigned long stack;

	stack = (unsigned long) task_stack_page(task);
	return in_stack(sp, info, STACK_TYPE_TASK, stack, stack + THREAD_SIZE);
}

static bool in_irq_stack(unsigned long sp, struct stack_info *info)
{
	unsigned long frame_size, top;

	frame_size = STACK_FRAME_OVERHEAD + sizeof(struct pt_regs);
	top = S390_lowcore.async_stack + frame_size;
	return in_stack(sp, info, STACK_TYPE_IRQ, top - THREAD_SIZE, top);
}

static bool in_nodat_stack(unsigned long sp, struct stack_info *info)
{
	unsigned long frame_size, top;

	frame_size = STACK_FRAME_OVERHEAD + sizeof(struct pt_regs);
	top = S390_lowcore.nodat_stack + frame_size;
	return in_stack(sp, info, STACK_TYPE_NODAT, top - THREAD_SIZE, top);
}

static bool in_restart_stack(unsigned long sp, struct stack_info *info)
{
	unsigned long frame_size, top;

	frame_size = STACK_FRAME_OVERHEAD + sizeof(struct pt_regs);
	top = S390_lowcore.restart_stack + frame_size;
	return in_stack(sp, info, STACK_TYPE_RESTART, top - THREAD_SIZE, top);
}

int get_stack_info(unsigned long sp, struct task_struct *task,
		   struct stack_info *info, unsigned long *visit_mask)
{
	if (!sp)
		goto unknown;

	task = task ? : current;

	/* Check per-task stack */
	if (in_task_stack(sp, task, info))
		goto recursion_check;

	if (task != current)
		goto unknown;

	/* Check per-cpu stacks */
	if (!in_irq_stack(sp, info) &&
	    !in_nodat_stack(sp, info) &&
	    !in_restart_stack(sp, info))
		goto unknown;

recursion_check:
	/*
	 * Make sure we don't iterate through any given stack more than once.
	 * If it comes up a second time then there's something wrong going on:
	 * just break out and report an unknown stack type.
	 */
	if (*visit_mask & (1UL << info->type)) {
		printk_deferred_once(KERN_WARNING
			"WARNING: stack recursion on stack type %d\n",
			info->type);
		goto unknown;
	}
	*visit_mask |= 1UL << info->type;
	return 0;
unknown:
	info->type = STACK_TYPE_UNKNOWN;
	return -EINVAL;
}

void save_stack_trace(struct stack_trace *trace)
{
	struct unwind_state state;

	unwind_for_each_frame(&state, current, NULL, 0) {
		if (trace->nr_entries >= trace->max_entries)
			break;
		if (trace->skip > 0)
			trace->skip--;
		else
			trace->entries[trace->nr_entries++] = state.ip;
	}
	if (trace->nr_entries < trace->max_entries)
		trace->entries[trace->nr_entries++] = ULONG_MAX;
}
EXPORT_SYMBOL_GPL(save_stack_trace);

void save_stack_trace_tsk(struct task_struct *tsk, struct stack_trace *trace)
{
	struct unwind_state state;

	unwind_for_each_frame(&state, tsk, NULL, 0) {
		if (trace->nr_entries >= trace->max_entries)
			break;
		if (in_sched_functions(state.ip))
			continue;
		if (trace->skip > 0)
			trace->skip--;
		else
			trace->entries[trace->nr_entries++] = state.ip;
	}
	if (trace->nr_entries < trace->max_entries)
		trace->entries[trace->nr_entries++] = ULONG_MAX;
}
EXPORT_SYMBOL_GPL(save_stack_trace_tsk);

void save_stack_trace_regs(struct pt_regs *regs, struct stack_trace *trace)
{
	struct unwind_state state;

	unwind_for_each_frame(&state, current, regs, 0) {
		if (trace->nr_entries >= trace->max_entries)
			break;
		if (trace->skip > 0)
			trace->skip--;
		else
			trace->entries[trace->nr_entries++] = state.ip;
	}
	if (trace->nr_entries < trace->max_entries)
		trace->entries[trace->nr_entries++] = ULONG_MAX;
}
EXPORT_SYMBOL_GPL(save_stack_trace_regs);
