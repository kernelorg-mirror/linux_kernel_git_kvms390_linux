/*
 *    DIAGNOSE X'2C4' instruction based HMC FTP services, useable on z/VM
 *
 *    Copyright IBM Corp. 2013
 *    Author(s): Ralf Hoppe (rhoppe@de.ibm.com)
 *
 */

#define KMSG_COMPONENT "hmcdrv"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/irq.h>
#include <linux/wait.h>
#include <linux/string.h>
#include <asm/ctl_reg.h>

#include "hmcdrv_ftp.h"
#include "diag_ftp.h"

#define DIAG_FTP_TIMEOUT	60 /* timeout (in seconds) of FTP request */

/* DIAGNOSE X'2C4' return codes in Ry */
#define DIAG_FTP_RET_OK 	0 /* HMC FTP started successully */
#define DIAG_FTP_RET_EBUSY	4 /* HMC FTP service currently busy */
#define DIAG_FTP_RET_EIO	8 /* HMC FTP service I/O error */
/* and an artifical extension */
#define DIAG_FTP_RET_EPERM	2 /* HMC FTP service privilege error */

/* FTP service status codes (after INTR at guest real location 133) */
#define DIAG_FTP_STAT_OK	0U /* request completed successfully */
#define DIAG_FTP_STAT_PGCC	4U /* program check condition */
#define DIAG_FTP_STAT_PGIOE	8U /* paging I/O error */
#define DIAG_FTP_STAT_TIMEOUT	12U /* timeout */
#define DIAG_FTP_STAT_EBASE	16U /* base of error codes from SCLP */
#define DIAG_FTP_STAT_LDFAIL	(DIAG_FTP_STAT_EBASE + 1U) /* failed */
#define DIAG_FTP_STAT_LDNPERM	(DIAG_FTP_STAT_EBASE + 2U) /* not allowed */
#define DIAG_FTP_STAT_LDRUNS	(DIAG_FTP_STAT_EBASE + 3U) /* runs */
#define DIAG_FTP_STAT_LDNRUNS	(DIAG_FTP_STAT_EBASE + 4U) /* not runs */

/* and an artifical extension */
#define DIAG_FTP_STAT_WAITING	1U /* a response code not used by HW */

/**
 * struct diag_ftp_ldfpl - load file FTP parameter list (LDFPL)
 * @bufaddr: real buffer adress (at 4k boundary)
 * @buflen: length of buffer
 * @offset: dir/file offset
 * @intparm: interruption parameter (unused)
 * @transferred: bytes transferred
 * @fsize: file size, filled on GET
 * @failaddr: failing address
 * @spare: padding
 * @fident: file name - ASCII
 */
struct diag_ftp_ldfpl {
	u64 bufaddr;
	u64 buflen;
	u64 offset;
	u64 intparm;
	u64 transferred;
	u64 fsize;
	u64 failaddr;
	u64 spare;
	u8 fident[HMCDRV_FTP_FIDENT_MAX];
} __packed;

static void diag_ftp_handler(struct ext_code extirq, unsigned int param32,
			     unsigned long param64);
static int diag_ftp_2c4(struct diag_ftp_ldfpl *fpl,
			enum hmcdrv_ftp_cmdid cmd);
static int diag_ftp_prepare(const struct hmcdrv_ftp_cmdspec *ftp);
static int diag_ftp_trigger(const struct hmcdrv_ftp_cmdspec *ftp);
static int diag_ftp_wait(void);

static DECLARE_WAIT_QUEUE_HEAD(diag_ftp_waitq);
static int diag_ftp_status = DIAG_FTP_STAT_OK;
static struct diag_ftp_ldfpl *diag_ftp_fpl; /* = NULL */

/**
 * diag_ftp_handler() - FTP services IRQ handler
 * @extirq: external interrupt (sub-) code
 * @param32: 32-bit interruption parameter from &struct diag_ftp_ldfpl
 * @param64: unused (for 64-bit interrupt parameters)
 */
static void diag_ftp_handler(struct ext_code extirq,
			     unsigned int param32,
			     unsigned long param64)
{
	if ((extirq.subcode >> 8) != 8)
		return; /* not a FTP services sub-code */

	inc_irq_stat(IRQEXT_FTP);
	diag_ftp_status = extirq.subcode & 0xffU;
	wake_up_interruptible(&diag_ftp_waitq);
}

/**
 * diag_ftp_2c4() - DIAGNOSE X'2C4' service call
 * @fpl: pointer to prepared LDFPL
 * @cmd: FTP command to be executed
 *
 * Performs a DIAGNOSE X'2C4' call with (input/output) FTP parameter list
 * @fpl and FTP function code @cmd. In case of an error the function does
 * nothing and returns an (negative) error code.
 *
 * Notes:
 * 1. This function only initiates a transfer, so the caller must wait
 *    for completion (asynchronous execution).
 * 2. The FTP parameter list @fpl must be aligned to a double-word boundary.
 * 3. fpl->bufaddr must be a real address, 4k aligned
 */
static int diag_ftp_2c4(struct diag_ftp_ldfpl *fpl,
			enum hmcdrv_ftp_cmdid cmd)
{
	int rc;
	unsigned long addr = virt_to_phys(fpl); /* make (guest) abs. addr */

	asm volatile(
		"	diag	%[addr],%[cmd],0x2c4\n"
		"0:	j	2f\n"
		"1:	la	%[rc],%[err]\n"
		"2:\n"
		EX_TABLE(0b, 1b)
		: [rc] "=r" (rc), "+m" (*fpl)
		: [cmd] "0" (cmd), [addr] "r" (addr),
		  [err] "i" (DIAG_FTP_RET_EPERM)
		: "cc");

	switch (rc) {
	case DIAG_FTP_RET_OK:
		rc = 0;
		break;
	case DIAG_FTP_RET_EBUSY:
		rc = -EBUSY;
		break;
	case DIAG_FTP_RET_EPERM:
		rc = -EPERM;
		break;
	case DIAG_FTP_RET_EIO:
	default:
		rc = -EIO;
		break;
	}

	return rc;
}

/**
 * diag_ftp_prepare() - prepare an allocated LDFPL
 * @ftp: pointer to FTP descriptor
 *
 * Return: 0 on success, else a (negative) error code
 */
static int diag_ftp_prepare(const struct hmcdrv_ftp_cmdspec *ftp)
{
	size_t len;

	len = strlcpy(diag_ftp_fpl->fident, ftp->fname,
		      sizeof(diag_ftp_fpl->fident));

	if (len >= HMCDRV_FTP_FIDENT_MAX)
		return -EINVAL;

	diag_ftp_fpl->transferred = 0;
	diag_ftp_fpl->fsize = 0;
	diag_ftp_fpl->offset = ftp->ofs;
	diag_ftp_fpl->buflen = ftp->len;
	diag_ftp_fpl->bufaddr = virt_to_phys(ftp->buf);

	return 0;
}

/**
 * diag_ftp_trigger() - start a FTP transfer
 * @ftp: pointer to FTP descriptor
 *
 * Return: 0 on success, else a (negative) error code
 */
static int diag_ftp_trigger(const struct hmcdrv_ftp_cmdspec *ftp)
{
	int rc = diag_ftp_prepare(ftp);

	if (rc)
		return rc;

	diag_ftp_status = DIAG_FTP_STAT_WAITING;
	rc = diag_ftp_2c4(diag_ftp_fpl, ftp->id);

	if (rc)
		diag_ftp_status = DIAG_FTP_STAT_OK;

	return rc;
}

/**
 * diag_ftp_wait() - wait for FTP transfer completion, with timeout
 *
 * Return: 0 on success, else a (negative) error code
 */
static int diag_ftp_wait()
{
	int rc;

	rc = wait_event_interruptible_timeout(
		diag_ftp_waitq,
		diag_ftp_status != DIAG_FTP_STAT_WAITING,
		HZ * DIAG_FTP_TIMEOUT);

	if (rc < 0)
		return rc; /* error (normally -ERESTARTSYS) */

	if (diag_ftp_status == DIAG_FTP_STAT_WAITING) {
		pr_warn("DIAG X'2C4' with timeout, after %ds\n",
			DIAG_FTP_TIMEOUT);
		return -EIO; /* map internal timeout to EIO */
	}

	pr_debug("completed DIAG X'2C4' after %d ms\n",
		 (HZ * DIAG_FTP_TIMEOUT - rc) * 1000 / HZ);

	return 0; /* no timeout, no error */
}

/**
 * diag_ftp_cmd() - executes a DIAG X'2C4' FTP command, targeting a HMC
 * @ftp: pointer to FTP command specification
 * @fsize: return of file size (or NULL if undesirable)
 *
 * Attention: Notice that this function is not reentrant - so the caller
 * must ensure locking.
 *
 * Return: number of bytes read/written or a (negative) error code
 */
ssize_t diag_ftp_cmd(const struct hmcdrv_ftp_cmdspec *ftp, size_t *fsize)
{
	ssize_t len;
	int rc;

	pr_debug("starting DIAG X'2C4' on '%s', requesting %zd bytes\n",
		 ftp->fname, ftp->len);

	rc = diag_ftp_trigger(ftp);

	if (rc)
		return rc;

	rc = diag_ftp_wait();

	pr_debug("status of DIAG X'2C4' is %u, with %lld/%lld bytes\n",
		 diag_ftp_status,
		 diag_ftp_fpl->transferred,
		 diag_ftp_fpl->fsize);

	if (rc)
		return rc;

	switch (diag_ftp_status) {
	case DIAG_FTP_STAT_OK: /* success */
		len = diag_ftp_fpl->transferred;

		if (fsize)
			*fsize = diag_ftp_fpl->fsize;
		break;

	case DIAG_FTP_STAT_LDNPERM:
		len = -EPERM;
		break;

	case DIAG_FTP_STAT_LDRUNS:
		len = -EBUSY;
		break;

	case DIAG_FTP_STAT_LDFAIL:
		len = -ENOENT; /* no such file or media */
		break;

	default:
		len = -EIO;
		break;
	}

	return len;
}

/**
 * diag_ftp_startup() - startup of FTP services, when running on z/VM
 *
 * Return: 0 on success, else an (negative) error code
 */
int diag_ftp_startup()
{
	int rc;

	diag_ftp_fpl = (struct diag_ftp_ldfpl *)
		get_zeroed_page(GFP_KERNEL | GFP_DMA);

	if (!diag_ftp_fpl)
		return -ENOMEM;

	rc = register_external_interrupt(0x2603, diag_ftp_handler);

	if (!rc) {
		ctl_set_bit(0, 63 - 22);
	} else {
		free_page((unsigned long)diag_ftp_fpl);
		diag_ftp_fpl = NULL;
	}

	return rc;
}

/**
 * diag_ftp_shutdown() - shutdown of FTP services, when running on z/VM
 */
void diag_ftp_shutdown()
{
	unregister_external_interrupt(0x2603, diag_ftp_handler);
	ctl_clear_bit(0, 63 - 22);
	free_page((unsigned long)diag_ftp_fpl);
	diag_ftp_fpl = NULL;
}
