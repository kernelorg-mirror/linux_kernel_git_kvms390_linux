#include <linux/module.h>
#include <linux/sort.h>
#include <asm/dis.h>
#include <asm/ptrace.h>
#include <asm/stacktrace.h>
#include <asm/unwind.h>
#include <asm/orc_types.h>
#include <asm/orc_lookup.h>

#define orc_warn(fmt, ...) \
	printk_deferred_once(KERN_WARNING pr_fmt("WARNING: " fmt), ##__VA_ARGS__)

extern int __start_orc_unwind_ip[];
extern int __stop_orc_unwind_ip[];
extern struct orc_entry __start_orc_unwind[];
extern struct orc_entry __stop_orc_unwind[];

static DEFINE_MUTEX(sort_mutex);
int *cur_orc_ip_table = __start_orc_unwind_ip;
struct orc_entry *cur_orc_table = __start_orc_unwind;

unsigned int lookup_num_blocks;
bool orc_init;

static inline unsigned long orc_ip(const int *ip)
{
	return (unsigned long) ip + *ip;
}

static struct orc_entry *__orc_find(int *ip_table, struct orc_entry *u_table,
				    unsigned int num_entries, unsigned long ip)
{
	int *first, *mid, *found, *last;

	if (!num_entries)
		return NULL;

	first = mid = found = ip_table;
	last = ip_table + num_entries - 1;

	/*
	 * Do a binary range search to find the rightmost duplicate of a given
	 * starting address.  Some entries are section terminators which are
	 * "weak" entries for ensuring there are no gaps.  They should be
	 * ignored when they conflict with a real entry.
	 */
	while (first <= last) {
		mid = first + ((last - first) / 2);

		if (orc_ip(mid) <= ip) {
			found = mid;
			first = mid + 1;
		} else
			last = mid - 1;
	}

	return u_table + (found - ip_table);
}

#ifdef CONFIG_MODULES
static struct orc_entry *orc_module_find(unsigned long ip)
{
	struct module *mod;

	mod = __module_address(ip);
	if (!mod || !mod->arch.orc_unwind || !mod->arch.orc_unwind_ip)
		return NULL;
	return __orc_find(mod->arch.orc_unwind_ip, mod->arch.orc_unwind,
			  mod->arch.num_orcs, ip);
}
#else
static struct orc_entry *orc_module_find(unsigned long ip)
{
	return NULL;
}
#endif

#ifdef CONFIG_DYNAMIC_FTRACE
static struct orc_entry *orc_find(unsigned long ip);

/*
 * Ftrace dynamic trampolines do not have orc entries of their own.
 * But they are copies of the ftrace entries that are static and
 * defined in ftrace_*.S, which do have orc entries.
 *
 * If the undwinder comes across a ftrace trampoline, then find the
 * ftrace function that was used to create it, and use that ftrace
 * function's orc entry, as the placement of the return code in
 * the stack will be identical.
 */
static struct orc_entry *orc_ftrace_find(unsigned long ip)
{
	unsigned long caller = (unsigned long) return_to_handler;

	/* Prevent unlikely recursion */
	if (ip == caller)
		return NULL;

	return orc_find(caller);
}
#else
static struct orc_entry *orc_ftrace_find(unsigned long ip)
{
	return NULL;
}
#endif

static struct orc_entry *orc_find(unsigned long ip)
{
	static struct orc_entry *orc;

	if (!orc_init)
		return NULL;

	/* For non-init vmlinux addresses, use the fast lookup table: */
	if (ip >= LOOKUP_START_IP && ip < LOOKUP_STOP_IP) {
		unsigned int idx, start, stop;

		idx = (ip - LOOKUP_START_IP) / LOOKUP_BLOCK_SIZE;

		if (unlikely((idx >= lookup_num_blocks - 1))) {
			orc_warn("WARNING: bad lookup idx: idx=%u num=%u ip=%pB\n",
				 idx, lookup_num_blocks, (void *) ip);
			return NULL;
		}

		start = orc_lookup[idx];
		stop = orc_lookup[idx + 1] + 1;

		if (unlikely((__start_orc_unwind + start >= __stop_orc_unwind) ||
			     (__start_orc_unwind + stop > __stop_orc_unwind))) {
			orc_warn("WARNING: bad lookup value: idx=%u num=%u start=%u stop=%u ip=%pB\n",
				 idx, lookup_num_blocks, start, stop, (void *) ip);
			return NULL;
		}

		return __orc_find(__start_orc_unwind_ip + start,
				  __start_orc_unwind + start, stop - start, ip);
	}

	/* vmlinux .init slow lookup: */
	if (init_kernel_text(ip))
		return __orc_find(__start_orc_unwind_ip, __start_orc_unwind,
				  __stop_orc_unwind_ip - __start_orc_unwind_ip, ip);

	/* Module lookup: */
	orc = orc_module_find(ip);
	if (orc)
		return orc;

	return orc_ftrace_find(ip);
}

static void orc_sort_swap(void *_a, void *_b, int size)
{
	struct orc_entry *orc_a, *orc_b;
	struct orc_entry orc_tmp;
	int *a = _a, *b = _b, tmp;
	int delta = _b - _a;

	/* Swap the .orc_unwind_ip entries: */
	tmp = *a;
	*a = *b + delta;
	*b = tmp - delta;

	/* Swap the corresponding .orc_unwind entries: */
	orc_a = cur_orc_table + (a - cur_orc_ip_table);
	orc_b = cur_orc_table + (b - cur_orc_ip_table);
	orc_tmp = *orc_a;
	*orc_a = *orc_b;
	*orc_b = orc_tmp;
}

static int orc_sort_cmp(const void *_a, const void *_b)
{
	const int *a = _a, *b = _b;
	unsigned long a_val = orc_ip(a);
	unsigned long b_val = orc_ip(b);

	if (a_val > b_val)
		return 1;
	if (a_val < b_val)
		return -1;
	/* two identical instruction addresses should *never* happen */
	return 0;
}

#ifdef CONFIG_MODULES
void unwind_module_init(struct module *mod, void *orc_ip, size_t orc_ip_size,
			void *orc, size_t orc_size)
{
	if (!orc || !orc_ip)
		return;

	WARN_ON_ONCE((orc_ip_size % sizeof(int)) != 0);
	WARN_ON_ONCE((orc_size % sizeof(int)) != 0);
	WARN_ON_ONCE(orc_size != orc_ip_size);

	mod->arch.orc_unwind_ip = (int *) orc_ip;
	mod->arch.orc_unwind = (struct orc_entry *) orc;
	mod->arch.num_orcs = orc_ip_size / sizeof(int);

	/*
	 * The 'cur_orc_*' globals allow the orc_sort_swap() callback to
	 * associate an .orc_unwind_ip table entry with its corresponding
	 * .orc_unwind entry so they can both be swapped.
	 */
	mutex_lock(&sort_mutex);
	cur_orc_ip_table = mod->arch.orc_unwind_ip;
	cur_orc_table = mod->arch.orc_unwind;
	sort(orc_ip, orc_ip_size / sizeof(int), sizeof(int),
	     orc_sort_cmp, orc_sort_swap);
	mutex_unlock(&sort_mutex);
}
#endif

void __init unwind_init(void)
{
	size_t orc_ip_size, orc_size, num_entries;
	struct orc_entry *orc;
	int i;

	orc_ip_size =
		(void *) __stop_orc_unwind_ip -	(void *) __start_orc_unwind_ip;
	orc_size =
		(void *) __stop_orc_unwind - (void *) __start_orc_unwind;
	num_entries = orc_ip_size / sizeof(int);
	if (!num_entries || orc_ip_size % sizeof(int) != 0 ||
	    orc_size % sizeof(struct orc_entry) != 0 ||
	    num_entries != orc_size / sizeof(struct orc_entry)) {
		orc_warn("WARNING: Bad or missing .orc_unwind table.  Disabling unwinder.\n");
		return;
	}

	/* Sort the .orc_unwind and .orc_unwind_ip tables: */
	sort(__start_orc_unwind_ip, num_entries, sizeof(int),
	     orc_sort_cmp, orc_sort_swap);

	/* Initialize the fast lookup table: */
	lookup_num_blocks = orc_lookup_end - orc_lookup;
	for (i = 0; i < lookup_num_blocks-1; i++) {
		orc = __orc_find(__start_orc_unwind_ip, __start_orc_unwind,
				 num_entries,
				 LOOKUP_START_IP + (LOOKUP_BLOCK_SIZE * i));
		if (!orc) {
			orc_warn("WARNING: Corrupt .orc_unwind table.  Disabling unwinder.\n");
			return;
		}

		orc_lookup[i] = orc - __start_orc_unwind;
	}

	/* Initialize the ending block: */
	orc = __orc_find(__start_orc_unwind_ip, __start_orc_unwind,
			 num_entries, LOOKUP_STOP_IP);
	if (!orc) {
		orc_warn("WARNING: Corrupt .orc_unwind table.  Disabling unwinder.\n");
		return;
	}
	orc_lookup[lookup_num_blocks-1] = orc - __start_orc_unwind;

	orc_init = true;
}

unsigned long unwind_get_return_address(struct unwind_state *state)
{
	if (unwind_done(state))
		return 0;
	return __kernel_text_address(state->ip) ? state->ip : 0;
}
EXPORT_SYMBOL_GPL(unwind_get_return_address);

static bool outside_of_stack(struct unwind_state *state, unsigned long sp)
{
	/*
	 * sp == state->sp can happen, e.g. a program check early in a
	 * function before the stack frame is created. This results in
	 * a pt_regs frame that returns to a function with the same sp.
	 */
	return (sp < state->sp) ||
		(sp + sizeof(struct stack_frame) > state->stack_info.end);
}

static bool update_stack_info(struct unwind_state *state, unsigned long sp)
{
	struct stack_info *info = &state->stack_info;
	unsigned long *mask = &state->stack_mask;

	/* New stack pointer leaves the current stack */
	if (get_stack_info(sp, state->task, info, mask) != 0 ||
	    !on_stack(info, sp, sizeof(struct stack_frame)))
		/* 'sp' does not point to a valid stack */
		return false;
	return true;
}

bool unwind_next_frame(struct unwind_state *state)
{
	struct orc_entry *orc;
	struct pt_regs *regs;
	unsigned long sp, ip;
	unsigned long *sa;
	int i;

	/* Don't let modules unload while we're reading their ORC data. */
	preempt_disable();

	/* End-of-stack check for user tasks: */
	if (state->regs && user_mode(state->regs))
		goto out_stop;

	/*
	 * Find the orc_entry associated with the text address.
	 *
	 * Decrement call return addresses by one so they work for sibling
	 * calls and calls to noreturn functions.
	 */
	orc = orc_find(state->regs ? state->ip : state->ip - 1);
	if (!orc)
		goto out_err;

	/* Find CFA and return address */
again:
	switch (orc->type) {
	default:
	case ORC_TYPE_REGISTER:
		/* Nothing special, just use %r14 and %r15 */
		regs = NULL;
		ip = state->gprs[orc->reg1];
		sp = state->gprs[orc->reg0] + orc->offset;
		break;
	case ORC_TYPE_RESTORE:
		/* Function with a stack frame, restore saved registers */
		regs = NULL;
		sa = (unsigned long *)
			(state->gprs[orc->reg0] + orc->offset);
		for (i = 6; i < 16; i++)
			if (orc->mask & (0x8000 >> i))
				break;
		for (; i < 16; i++, sa++) {
			if (orc->mask & (0x8000 >> i))
				state->gprs[i] = *sa;
		}
		ip = state->gprs[14];
		sp = state->gprs[15];
		break;
	case ORC_TYPE_PTREGS:
		/* Interrupt frame with a struct pt_regs */
		regs = (struct pt_regs *)
			(state->gprs[orc->reg0] + orc->offset);
		memcpy(state->gprs, regs->gprs, 16*sizeof(unsigned long));
		ip = regs->psw.addr;
		sp = state->gprs[15];
		break;
	case ORC_TYPE_EXPOLINE:
		/* Use expoline branch target address to find the ORC info */
		orc = orc_find(state->gprs[orc->reg0]);
		if (!orc)
			goto out_err;
		goto again;
	}

	/* Check if the stack info needs an update */
	if (unlikely(outside_of_stack(state, sp))) {
		if (!update_stack_info(state, sp))
			goto out_err;
	}

	/* Decode any ftrace redirection */
	if (ip == (unsigned long) return_to_handler)
		ip = ftrace_graph_ret_addr(state->task, &state->graph_idx,
					   ip, NULL);

	/* Update unwind state */
	state->sp = sp;
	state->ip = ip;
	state->regs = regs;

	preempt_enable();
	return true;

out_err:
	state->error = true;
out_stop:
	state->stack_info.type = STACK_TYPE_UNKNOWN;
	preempt_enable();
	return false;
}
EXPORT_SYMBOL_GPL(unwind_next_frame);

void __unwind_start(struct unwind_state *state, struct task_struct *task,
		    struct pt_regs *regs, unsigned long sp)
{
	struct stack_info *info = &state->stack_info;
	unsigned long *mask = &state->stack_mask;
	struct stack_frame *sf;

	memset(state, 0, sizeof(*state));
	state->task = task;
	state->regs = regs;
	state->reliable = true;

	if (regs) {
		/* Get the registers from the pt_regs structure */
		if (user_mode(regs)) {
			info->type = STACK_TYPE_UNKNOWN;
			return;
		}
		memcpy(state->gprs, regs->gprs, 16*sizeof(unsigned long));
		state->ip = READ_ONCE_TASK_STACK(state->task, regs->psw.addr);
		state->sp = READ_ONCE_TASK_STACK(state->task, regs->gprs[15]);
	} else if (task == current) {
		/* Store current instruction pointer and gprs */
		asm volatile(
			"	basr	%[ip],0\n"
			"	stmg	0,15,%[gprs]\n"
			: [ip] "=d" (state->ip), [gprs] "=Q" (state->gprs));
		state->sp = state->gprs[15];
	} else {
		/* Get registers of an inactive task */
		sf = (struct stack_frame *) task->thread.ksp;
		memset(state->gprs, 0, 6*sizeof(unsigned long));
		memcpy(state->gprs + 6, sf->gprs, 10*sizeof(unsigned long));
		/* Get the state after return from __switch_to */
		state->sp = state->gprs[15];
		state->ip = state->gprs[14];
	}

	/* Get current stack pointer and initialize stack info */
	if (get_stack_info(sp, task, info, mask) != 0 ||
	    !on_stack(info, sp, sizeof(struct stack_frame))) {
		/* Something is wrong with the stack pointer */
		info->type = STACK_TYPE_UNKNOWN;
		state->error = true;
		return;
	}

	/* When starting from regs, skip to the next frame */
	if (regs) {
		unwind_next_frame(state);
		return;
	}

	/* Skip through the call chain to the specified starting frame */
	while (!unwind_done(state) &&
	       (!on_stack(&state->stack_info, sp, sizeof(*sf)) ||
			state->sp <= sp))
		unwind_next_frame(state);
}
EXPORT_SYMBOL_GPL(__unwind_start);
