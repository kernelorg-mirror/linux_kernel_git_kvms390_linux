
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/smp.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <asm/sigp.h>
#include <asm/io.h>
#include <asm/facility.h>

MODULE_DESCRIPTION("zKVM SIGP tests");
MODULE_LICENSE("GPL");

#ifndef SIGP_STATUS_INVALID_ORDER
#define SIGP_STATUS_INVALID_ORDER	2
#endif

#define WITH_INTERRUPT_TESTS	0
#define WITH_STOP_TESTS		1
#define WITH_DEBUG		0

#if 1
# define dprintk printk
#else
# define dprintk(...)
#endif

static int src_cpu_id;

struct cpu_thread_data {
	volatile u16 id;		/* CPU address */
	volatile u32 counter;
};

static inline int _sigp(u16 addr, u8 order, u32 parm, u32 *status)
{
	register unsigned int reg1 asm ("1") = parm;
	int cc;

	asm volatile(
		"	sigp	%1,%2,0(%3)\n"
		"	ipm	%0\n"
		"	srl	%0,28\n"
		: "=d" (cc), "+d" (reg1) : "d" (addr), "a" (order)
		: "cc", "memory");
	if (status && cc == 1)
		*status = reg1;
	return cc;
}

#if WITH_STOP_TESTS
static void _memcpy_absolute(void *dest, void *src, size_t count)
{
	unsigned long cr0, flags, prefix;

	flags = arch_local_irq_save();
	__ctl_store(cr0, 0, 0);
	__ctl_clear_bit(0, 28); /* disable lowcore protection */
	prefix = store_prefix();
	if (prefix) {
		/*local_mcck_disable();*/
		set_prefix(0);
		memcpy(dest, src, count);
		set_prefix(prefix);
		/*local_mcck_enable();*/
	} else {
		memcpy(dest, src, count);
	}
	__ctl_load(cr0, 0, 0);
	arch_local_irq_restore(flags);
}
#endif

static int destcpu_run(void *ptr)
{
	struct cpu_thread_data *data = ptr;
	int my_cpu_id;

	preempt_disable();

	my_cpu_id = smp_processor_id();
	if (my_cpu_id == src_cpu_id) {
		preempt_enable();
		pr_err("ERROR: Source CPU ID is the same as dest CPU id!\n");
		return -1;
	}

	data->id = my_cpu_id;
	while (!kthread_should_stop()) {
		data->counter += 1;
		mb();	/* Make sure that it really gets written to memory */
	}

	preempt_enable();
	return 0;
}

static bool is_alive(struct cpu_thread_data *dest, int timeout)
{
	int i;
	u32 start = dest->counter;

	for (i = timeout; i > 0; i--) {
		mb();	/* Make sure that we really read new values from mem */
		if (dest->counter != start)
			return true;
		mdelay(1);
	}
	return false;
}

/* STOP destination */
#if WITH_STOP_TESTS
static int send_sigp_stop(struct cpu_thread_data *dest)
{
	int ret;

	ret = _sigp(dest->id, SIGP_STOP, 0, NULL);
	if (ret) {
		pr_err("ERROR: SIGP_STOP returned CC=%i\n", ret);
		return ret;
	}
	udelay(10);
	if (is_alive(dest, 800)) {
		pr_err("ERROR: Sent SIGP_STOP, but dest is still alive!\n");
		return -EBUSY;
	}
	return 0;
}
#endif

/* START destination */
static int send_sigp_start(struct cpu_thread_data *dest)
{
	int ret, i;

	for (i = 0; i < 100; i++) {
		ret = _sigp(dest->id, SIGP_START, 0, NULL);
		if (ret != 2)
			break;
		udelay(10);
	}
	if (ret) {
		pr_err("ERROR: SIGP_START returned CC=%i\n", ret);
		return ret;
	}
	udelay(10);
	if (!is_alive(dest, 2000)) {
		pr_err("ERROR: SIGP_START: dest still dead!\n");
		return -EBUSY;
	}
	return 0;
}

/* Various START + STOP tests */
static int test_sigp_start_stop(struct cpu_thread_data *dest)
{
	int ret;

#if WITH_STOP_TESTS
	/* Test STOP + START */
	dprintk("SIGP test: Running STOP + START...\n");
	ret = send_sigp_stop(dest);
	if (ret)
		return ret;

	ret = send_sigp_start(dest);
	if (ret)
		return ret;

	/* Send two STOP requests */
	dprintk("SIGP test: Sending two STOPs...\n");
	ret = send_sigp_stop(dest);
	if (ret)
		return ret;
	udelay(10);
	ret = send_sigp_stop(dest);
	if (ret)
		return ret;
#endif

	/* Send two START requests */
	dprintk("SIGP test: Sending two STARTs...\n");
	ret = send_sigp_start(dest);
	if (ret)
		return ret;
	ret = send_sigp_start(dest);
	if (ret)
		return ret;

	dprintk("SIGP test: STOP with illegal CPU id...\n");
	ret = _sigp(-4711, SIGP_STOP, 0, NULL);
	if (ret != 3) {
		pr_err("ERROR: SIGP_STOP with illegal ID returned bad CC=%i!", ret);
		return ret;
	}
	dprintk("SIGP test: START with illegal CPU id...\n");
	ret = _sigp(-4711, SIGP_START, 0, NULL);
	if (ret != 3) {
		pr_err("ERROR: SIGP_START with illegal ID returned bad CC=%i!", ret);
		return ret;
	}

	return 0;
}

/* SENSE tests */
static int test_sigp_sense(struct cpu_thread_data *dest)
{
	int ret;
	u32 status = 0;

	dprintk("SIGP test: SIGP_SENSE with illegal ID...\n");
	ret = _sigp(-4711, SIGP_SENSE, 0, &status);
	if (ret != 3) {
		pr_err("ERROR: SIGP_SENSE with illegal ID returned CC=%i\n", ret);
		return -EINVAL;
	}

	dprintk("SIGP test: SIGP_SENSE (running) ...\n");
	ret = _sigp(dest->id, SIGP_SENSE, 0, &status);
	if (ret != 0 && ret != 1) {
		pr_err("ERROR: SIGP_SENSE (running) returned CC=%i\n", ret);
		return -EINVAL;
	}

#if WITH_STOP_TESTS
	ret = send_sigp_stop(dest);
	if (ret)
		return ret;
	dprintk("SIGP test: SIGP_SENSE (stopped) ...\n");
	ret = _sigp(dest->id, SIGP_SENSE, 0, &status);
	if (ret != 1 || (status & SIGP_STATUS_STOPPED) == 0) {
		pr_err("ERROR: SIGP_SENSE (stopped) returned CC=%i, status=0x%x\n",
			ret, status);
		send_sigp_start(dest);
		return -EINVAL;
	}
	ret = send_sigp_start(dest);
	if (ret)
		return ret;
#endif

	return 0;
}

/* SENSE RUNNING tests */
static int test_sigp_sense_running(struct cpu_thread_data *dest)
{
	int ret;
	u32 status = 0;

	dprintk("SIGP test: SIGP_SENSE RUNNING with illegal ID...\n");
	ret = _sigp(-4711, SIGP_SENSE_RUNNING, 0, &status);
	if (ret != 3) {
		pr_err("ERROR: SIGP_SENSE RUNNING with illegal ID returned CC=%i\n", ret);
		return -EINVAL;
	}

	dprintk("SIGP test: SIGP_SENSE_RUNNING (running) ...\n");
	ret = _sigp(dest->id, SIGP_SENSE_RUNNING, 0, &status);
	if (ret != 0 && (ret != 1 || status != SIGP_STATUS_NOT_RUNNING)) {
		pr_err("ERROR: SIGP_SENSE_RUNNING (running) returned CC=%i, status=0x%x\n",
			ret, status);
		return -EINVAL;
	}

#if WITH_STOP_TESTS
	ret = send_sigp_stop(dest);
	if (ret)
		return ret;
	dprintk("SIGP test: SIGP_SENSE_RUNNING (stopped) ...\n");
	ret = _sigp(dest->id, SIGP_SENSE_RUNNING, 0, &status);
	if (ret != 1 || status != SIGP_STATUS_NOT_RUNNING) {
		pr_err("ERROR: SIGP_SENSE_RUNNING (stopped) returned CC=%i, status=0x%x\n",
			ret, status);
		send_sigp_start(dest);
		return -EINVAL;
	}
	ret = send_sigp_start(dest);
	if (ret)
		return ret;
#endif

	return 0;
}

/* STORE STATUS tests */
static int test_sigp_store_status(struct cpu_thread_data *dest)
{
#if WITH_DEBUG
	int i;
#endif
	int ret;
	u32 status = 0, buf32;
	u8 *buf, *ptr;

	buf = kmalloc(1023, GFP_DMA);
	if (!buf)
		return -ENOMEM;

	ptr = (u8 *)((long)(buf + 511) & ~511L);      /* Align buffer */
	buf32 = (u32)(long)virt_to_phys(ptr);
	memset(ptr, 0xaa, 512);

	/* Send STORE STATUS while CPU is still running */
	dprintk("SIGP test: STORE_STATUS_AT_ADDRESS while CPU still running...\n");
	ret = _sigp(dest->id, SIGP_STORE_STATUS_AT_ADDRESS, buf32, &status);
	if (ret != 1 || status != 1 << (63 - 54)) {
		pr_err("ERROR: SIGP_STORE_STATUS_AT_ADDRESS returned CC=%i\n", ret);
		ret = -EINVAL;
		goto free_mem;
	}

	/* Send STORE STATUS with illegal CPU id */
	dprintk("SIGP test: STORE_STATUS_AT_ADDRESS with illegal ID...\n");
	ret = _sigp(-4711, SIGP_STORE_STATUS_AT_ADDRESS, buf32, &status);
	if (ret != 3) {
		pr_err("ERROR: SIGP_STORE_STATUS_AT_ADDRESS with illegal ID returned CC=%i\n", ret);
		ret = -EINVAL;
		goto free_mem;
	}

#if WITH_STOP_TESTS
	ret = send_sigp_stop(dest);
	if (ret)
		goto free_mem;

	/* Send STORE STATUS */
	dprintk("SIGP test: STORE_STATUS_AT_ADDRESS...\n");
	ret = _sigp(dest->id, SIGP_STORE_STATUS_AT_ADDRESS, buf32, &status);
	if (ret != 0)
		pr_err("ERROR: SIGP_STORE_STATUS_AT_ADDRESS returned CC=%i\n",
		       ret);

	ret |= send_sigp_start(dest);
	if (ret != 0) {
		ret = -EINVAL;
		goto free_mem;
	}

#if WITH_DEBUG
	for (i = 0; i < 512; i++) {
		if ((i&15) == 0)
			pr_info("\n\t");
		pr_info("%02x ", ptr[i]);
	}
#endif

	/* Sanity check -- assumes that destination CPU is running in 64-bit */
	if (ptr[259] != 0x01 || ptr[260] != 0x80 || ptr[261] || ptr[262]
	    || ptr[263] || ptr[304]) {
		pr_err("ERROR: SIGP_STORE_STATUS_AT_ADDRESS stored bad data!\n");
		dprintk("SIGP STATUS buf: %02x %02x %02x %02x %02x %02x\n",
			ptr[259], ptr[260], ptr[261], ptr[262], ptr[263], ptr[304]);
		ret = -EINVAL;
		goto free_mem;
	}

	/* Test the arch mode ID and status in low-core */
	memset(ptr, 0xaa, 512);
	_memcpy_absolute((void *)0xa3, (void *)virt_to_phys(ptr), 1);
	dprintk("SIGP test: STOP_AND_STORE_STATUS...\n");
	ret = _sigp(dest->id, SIGP_STOP_AND_STORE_STATUS, 0, &status);
	if (ret != 0) {
		pr_err("ERROR: STOP_AND_STORE_STATUS returned CC=%i\n", ret);
		ret = -EINVAL;
		goto free_mem;
	}
	ret = send_sigp_start(dest);
	if (ret != 0)
		goto free_mem;
	_memcpy_absolute((void *)virt_to_phys(ptr), (void *)0xa3, 1);
	if (ptr[0] != 0x01) {
		pr_err("ERROR: STOP_AND_STORE_STATUS returned bad value!\n");
		ret = -EINVAL;
		goto free_mem;
	}

	_memcpy_absolute((void *)virt_to_phys(ptr), (void *)4608, 512);
	/* Sanity check -- assumes that destination CPU is running in 64-bit */
	if (ptr[259] != 0x01 || ptr[260] != 0x80 || ptr[261] || ptr[262]
	    || ptr[263] || ptr[304]) {
		pr_err("ERROR: SIGP_STOP_AND_STORE_STATUS stored bad data!\n");
		dprintk("SIGP STOPnSTORE STATUS buf: %02x %02x %02x %02x %02x %02x\n",
			ptr[259], ptr[260], ptr[261], ptr[262], ptr[263], ptr[304]);
		ret = -EINVAL;
		goto free_mem;
	}
#endif

	/* Send STOP AND STORE STATUS with illegal CPU id */
	dprintk("SIGP test: STOP_AND_STORE_STATUS with illegal ID...\n");
	ret = _sigp(-4711, SIGP_STOP_AND_STORE_STATUS, 0, &status);
	if (ret != 3) {
		pr_err("ERROR: SIGP_STOP_AND_STORE with illegal ID returned CC=%i\n", ret);
		goto free_mem;
	}
	ret = 0;

free_mem:
	kfree(buf);
	return ret;
}

/* STORE ADDITIONAL STATUS tests */
static int test_sigp_store_adtl_status(struct cpu_thread_data *dest)
{
#if WITH_DEBUG
	int i;
#endif
	int ret;
	u32 status = 0, buf32;
	u8 *buf, *ptr;

	if (!test_facility(129))
		return 0;

	buf = kmalloc(2047, GFP_DMA);
	if (!buf)
		return -ENOMEM;

	ptr = (u8 *)((long)(buf + 1023) & ~1023L);      /* Align buffer */
	buf32 = (u32)(long)virt_to_phys(ptr);
	memset(ptr, 0xaa, 512);

	/* Send STORE ADDITIONAL STATUS while CPU is still running */
	dprintk("SIGP test: STORE_ADTL_STATUS_ADDR while CPU running...\n");
	ret = _sigp(dest->id, SIGP_STORE_ADDITIONAL_STATUS, buf32, &status);
	if (ret != 1 || status != 1 << (63 - 54)) {
		pr_err("ERROR: STORE_ADTL_STATUS_ADDR returned CC=%i\n", ret);
		ret = -EINVAL;
		goto free_mem;
	}

#if WITH_STOP_TESTS
	ret = send_sigp_stop(dest);
	if (ret)
		goto free_mem;

	/* Send STORE ADDITIONAL STATUS with illegal CPU id */
	dprintk("SIGP test: STORE_ADTL_STATUS_ADDR with illegal ID...\n");
	ret = _sigp(-4711, SIGP_STORE_ADDITIONAL_STATUS, buf32, &status);
	if (ret != 3) {
		pr_err("ERROR: STORE_ADTL_STATUS_ADDR with illegal ID CC=%i\n",
		       ret);
		ret = -EINVAL;
		goto free_mem;
	}

	/* Send STORE ADDITIONAL STATUS */
	dprintk("SIGP test: STORE_ADTL_STATUS_ADDR...\n");
	ret = _sigp(dest->id, SIGP_STORE_ADDITIONAL_STATUS, buf32, &status);
	if (ret != 0)
		pr_err("ERROR: STORE_ADTL_STATUS_ADDR returned CC=%i\n", ret);

	ret |= send_sigp_start(dest);
	if (ret != 0) {
		ret = -EINVAL;
		goto free_mem;
	}

#if WITH_DEBUG
	for (i = 0; i < 512; i++) {
		if (ptr[i] == 0xaa) {
			pr_err("ERROR: Data at byte %i not written\n", i);
			ret = -EINVAL;
			goto free_mem
		}
		if ((i & 15) == 0)
			dprintk("\n\t");
		dprintk("%02x ", ptr[i]);
	}
	dprintk("\n");
#endif
#endif

free_mem:
	kfree(buf);
	return ret;
}

/* SET PREFIX tests */
static int test_sigp_set_prefix(struct cpu_thread_data *dest)
{
	u32 status = 0;
	int ret;

	dprintk("SIGP test: SET_PREFIX with illegal CPU id...\n");
	ret = _sigp(-4711, SIGP_SET_PREFIX, 0, NULL);
	if (ret != 3) {
		pr_err("ERROR: SIGP_SET_PREFIX returned CC=%i\n", ret);
		return -EINVAL;
	}

	dprintk("SIGP test: SET_PREFIX with running CPU...\n");
	ret = _sigp(dest->id, SIGP_SET_PREFIX, 0, &status);
	if (ret != 1 || status != SIGP_STATUS_INCORRECT_STATE) {
		pr_err("ERROR: SIGP_SET_PREFIX returned CC=%i, status=0x%x\n",
			ret, status);
		return -EINVAL;
	}

	return 0;
}

/* EMERGENCY tests */
static int test_sigp_emergency(struct cpu_thread_data *dest)
{
	u32 status = 0;
	int ret;

#if WITH_INTERRUPT_TESTS
	dprintk("SIGP test: Emergency signal...\n");
	ret = _sigp(dest->id, SIGP_EMERGENCY_SIGNAL, 0, NULL);
	if (ret != 0) {
		pr_err("ERROR: SIGP Emergency signal returned CC=%i\n", ret);
		return -EINVAL;
	}
#endif

	dprintk("SIGP test: Emergency signal with illegal ID...\n");
	ret = _sigp(-4711, SIGP_EMERGENCY_SIGNAL, 0, NULL);
	if (ret != 3) {
		pr_err("ERROR: SIGP Emergency signal with illegal ID returned CC=%i\n", ret);
		return -EINVAL;
	}

#if WITH_INTERRUPT_TESTS
	dprintk("SIGP test: Conditional emergency signal...\n");
	ret = _sigp(dest->id, SIGP_COND_EMERGENCY_SIGNAL, 4711, &status);
	if (ret != 0 && ret != 1) {
		pr_err("ERROR: SIGP conditional emergency signal returned CC=%i"
			", status = 0x%x\n", ret, status);
		return -EINVAL;
	}
#endif

	dprintk("SIGP test: Conditional emergency signal with illegal ID...\n");
	ret = _sigp(-4711, SIGP_COND_EMERGENCY_SIGNAL, 4711, &status);
	if (ret != 3) {
		pr_err("ERROR: SIGP conditional emergency signal with illegal "
			"ID returned CC=%i, status = 0x%x\n", ret, status);
		return -EINVAL;
	}

	return 0;
}

/* EXTERNAL CALL tests */
static int test_sigp_extcall(struct cpu_thread_data *dest)
{
	int ret;

#if WITH_INTERRUPT_TESTS
	dprintk("SIGP test: External call...\n");
	ret = _sigp(dest->id, SIGP_EXTERNAL_CALL, 0, NULL);
	if (ret != 0) {
		pr_err("ERROR: SIGP External call returned CC=%i\n", ret);
		return -EINVAL;
	}
#endif

	dprintk("SIGP test: External call with illegal ID...\n");
	ret = _sigp(-4711, SIGP_EXTERNAL_CALL, 0, NULL);
	if (ret != 3) {
		pr_err("ERROR: SIGP External call with illegal ID returned CC=%i\n", ret);
		return -EINVAL;
	}

	return 0;
}

/* SET ARCHITECTURE tests */
static int test_sigp_set_architecture(struct cpu_thread_data *dest)
{
	u32 status = 0;
	int ret;

	dprintk("SIGP test: SET_ARCH with illegal mode...\n");
	ret = _sigp(dest->id, SIGP_SET_ARCHITECTURE, 4711, &status);
	if (ret != 1 || (status != SIGP_STATUS_INVALID_PARAMETER
			 && status != SIGP_STATUS_INCORRECT_STATE)) {
		pr_err("ERROR: SIGP SET_ARCH returned CC=%i, status = 0x%x\n",
			ret, status);
		return -EINVAL;
	}

	dprintk("SIGP test: SET_ARCH with running CPUs...\n");
	status = 0;
	ret = _sigp(dest->id, SIGP_SET_ARCHITECTURE, 0, &status);
	if (ret != 1 || status != SIGP_STATUS_INCORRECT_STATE) {
		pr_err("ERROR: SIGP SET_ARCH returned CC=%i, status = 0x%x\n",
			ret, status);
		return -EINVAL;
	}

	return 0;
}

/* Illegal parameters */
static int test_sigp_illegal(struct cpu_thread_data *dest)
{
	u32 status = 0;
	int ret;

	dprintk("SIGP test: CPU_RESET with illegal ID...\n");
	ret = _sigp(-4711, SIGP_CPU_RESET, 0, NULL);
	if (ret != 3) {
		pr_err("ERROR: CPU_RESET with invalid ID returned CC=%i\n",
			ret);
		return -EINVAL;
	}

	dprintk("SIGP test: Illegal order code...\n");
	ret = _sigp(dest->id, 0xff, 0, &status);
	if (ret != 1 || status != SIGP_STATUS_INVALID_ORDER) {
		pr_err("ERROR: SIGP with invalid order returned CC=%i, status=0x%x\n",
			ret, status);
		return -EINVAL;
	}

	dprintk("SIGP test: Illegal order code and illegal CPU id...\n");
	ret = _sigp(-4711, 0xff, 0, &status);
	if (ret != 3) {
		pr_err("ERROR: SIGP with invalid order+CPU returned CC=%i, status=0x%x\n",
			ret, status);
		return -EINVAL;
	}

	return 0;
}

static int test_sigp(void)
{
	struct task_struct *destthrd;
	struct cpu_thread_data destcpu;
	int i, ret = -1;

	/* Init thread on destination CPU */
	src_cpu_id = smp_processor_id();
	destcpu.id = 0xffff;
	destthrd = kthread_create_on_node(destcpu_run, &destcpu,
					  cpu_to_node(src_cpu_id ^ 1),
					  "sigp-test-cpu");
	if (IS_ERR(destthrd)) {
		pr_err("ERROR: could not create thread!\n");
		return -ENOMEM;
	}
	kthread_bind(destthrd, src_cpu_id ^ 1);
	wake_up_process(destthrd);
	i = 0;
	while (destcpu.id == 0xffff) {
		if (i++ == 200) {
			pr_err("ERROR: timed out while starting thread!\n");
			return -ENXIO;
		}
		msleep(20);
	}
	dprintk("SIGP test: Source CPU ID = %i\n", src_cpu_id);
	dprintk("SIGP test: Destination CPU ID = %i\n", destcpu.id);
	if (!is_alive(&destcpu, 2000)) {
		pr_err("ERROR: thread is not alive!\n");
		goto out;
	}

	ret = test_sigp_start_stop(&destcpu);
	if (ret)
		goto out;

	ret = test_sigp_sense(&destcpu);
	if (ret)
		goto out;

	ret = test_sigp_sense_running(&destcpu);
	if (ret)
		goto out;

	ret = test_sigp_store_status(&destcpu);
	if (ret)
		goto out;

	ret = test_sigp_store_adtl_status(&destcpu);
	if (ret)
		goto out;

	ret = test_sigp_set_prefix(&destcpu);
	if (ret)
		goto out;

	ret = test_sigp_set_architecture(&destcpu);
	if (ret)
		goto out;

	ret = test_sigp_emergency(&destcpu);
	if (ret)
		goto out;

	ret = test_sigp_extcall(&destcpu);
	if (ret)
		goto out;

	ret = test_sigp_illegal(&destcpu);
	if (ret)
		goto out;

	dprintk("SIGP test: Tests finished successfully!\n");
out:
	dprintk("SIGP test: Stopping destination thread...\n");
	kthread_stop(destthrd);

	return ret;
}

static int __init sigptest_mod_init(void)
{
	int ret;

	pr_info("----- SIGP TEST MODULE STARTED -----\n");

	ret = test_sigp();

	pr_info("SIGP tests done.\n");

	if (ret > 0)
		ret = -EIO;

	return ret;
}

static void __exit sigptest_mod_exit(void)
{
	pr_info("----- SIGP TEST MODULE STOPPED -----\n");
}

module_init(sigptest_mod_init);
module_exit(sigptest_mod_exit);
