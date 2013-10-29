/*
 *    SCLP Event Type (ET) 7 - Diagnostic Test FTP Services, useable on LPAR
 *
 *    Copyright IBM Corp. 2013
 *    Author(s): Ralf Hoppe (rhoppe@de.ibm.com)
 *
 */

#define KMSG_COMPONENT "hmcdrv"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/wait.h>
#include <linux/string.h>

#ifdef DEBUG
#include <linux/jiffies.h>
#include <asm/sysinfo.h>
#include <asm/ebcdic.h>
#endif	/* DEBUG */

#include "sclp.h"
#include "sclp_diag.h"
#include "sclp_ftp.h"

#define SCLP_FTP_TIMEOUT    60 /* timeout (in seconds) of FTP request */

static void sclp_ftp_txcb(struct sclp_req *req, void *data);
static void sclp_ftp_rxcb(struct evbuf_header *evbuf);
static int sclp_ftp_et7(struct sclp_req *req);
static int sclp_ftp_prepare(const struct hmcdrv_ftp_cmdspec *ftp);
static int sclp_ftp_trigger(const struct hmcdrv_ftp_cmdspec *ftp);
static int sclp_ftp_wait(void);

static DECLARE_WAIT_QUEUE_HEAD(sclp_ftp_waitq);
static int sclp_ftp_status = SCLP_REQ_FILLED;
static struct sclp_diag_sccb *sclp_ftp_sccb;
static struct sclp_req sclp_ftp_requ = {
	.command = SCLP_CMDW_WRITE_EVENT_DATA,
	.callback = sclp_ftp_txcb,
	.callback_data = NULL
};

#ifdef DEBUG
static unsigned long sclp_ftp_jiffies; /* jiffies at start of command */
#endif /* DEBUG */

/*
 * SCLP descriptor, to be passed to function sclp_register()
 */
static struct sclp_register sclp_ftp_event = {
	.send_mask = EVTYP_DIAG_TEST_MASK,    /* want tx events */
	.receive_mask = EVTYP_DIAG_TEST_MASK, /* want rx events */
	.receiver_fn = sclp_ftp_rxcb,	      /* async callback (rx) */
	.state_change_fn = NULL,
	.pm_event_fn = NULL,
};

/**
 * sclp_ftp_txcb() - Diagnostic Test FTP services SCLP command callback
 *
 * Note: If a request is NOT accepted by the SCLP layer (see "processed-buffer"
 * flag and response code in SCLP header), then we MUST skip the receive wait,
 * because sclp_ftp_rxcb() is NOT called and so the second call to
 * wait_event_timeout() would produce a timeout). In the other case we MUST wait
 * for the ET7 event (RX).
 */
static void sclp_ftp_txcb(struct sclp_req *req, void *data)
{
	struct sclp_diag_sccb *sccb = (struct sclp_diag_sccb *) req->sccb;

	pr_debug("SCLP (ET7) TX-IRQ, SCCB @ 0x%p: %*phN\n", sccb, 24, sccb);

	if ((req->status == SCLP_REQ_DONE) &&
	    (sccb->evbuf.hdr.flags & 0x80) && /* "processed-buffer" */
	    ((sccb->hdr.response_code & 0xffU) == 0x20U)) {
		sclp_ftp_status = SCLP_REQ_FILLED;
	} else {
		sclp_ftp_status = SCLP_REQ_FAILED;
	}

	wake_up_interruptible(&sclp_ftp_waitq);
}

/**
 * sclp_ftp_rxcb() - Diagnostic Test FTP services receiver event callback
 */
static void sclp_ftp_rxcb(struct evbuf_header *evbuf)
{
	struct sclp_diag_evbuf *diag = (struct sclp_diag_evbuf *) evbuf;

	/* first check for Diagnostic Test FTP Service
	 */
	if ((evbuf->type != EVTYP_DIAG_TEST) ||
	    (diag->route != SCLP_DIAG_FTP_ROUTE) ||
	    (diag->mdd.ftp.pcx != SCLP_DIAG_FTP_XPCX) ||
	    (evbuf->length < SCLP_DIAG_FTP_EVBUF_LEN))
		return;

	pr_debug("SCLP (ET7) RX-IRQ, Event @ 0x%p: %*phN\n",
		 evbuf, 24, evbuf);

	/* because the event buffer is located in a page,
	 * which is owned by the SCLP core, all data of
	 * interest must be copied
	 */
	sclp_ftp_sccb->evbuf.mdd.ftp.ldflg = diag->mdd.ftp.ldflg;
	sclp_ftp_sccb->evbuf.mdd.ftp.fsize = diag->mdd.ftp.fsize;
	sclp_ftp_sccb->evbuf.mdd.ftp.length = diag->mdd.ftp.length;

	/* the error indication is by 'sclp_ftp_sccb->evbuf.mdd.ftp.ldflg',
	 * unless there is an I/O error signalled by 'sclp_ftp_status'
	 */
	if (sclp_ftp_status != SCLP_REQ_FAILED)
		sclp_ftp_status = SCLP_REQ_DONE;

	wake_up_interruptible(&sclp_ftp_waitq);
}

/**
 * sclp_ftp_et7() - start a Diagnostic Test FTP Service SCLP request
 * @req: SCLP request
 *
 * Return: 0 on success, else a (negative) error code
 */
static int sclp_ftp_et7(struct sclp_req *req)
{
	req->status = SCLP_REQ_FILLED;
	return sclp_add_request(req);
}

/**
 * sclp_ftp_prepare() - prepares the Diagnostic Test FTP Service (ET7) SCCB
 * in variable 'sclp_ftp_sccb' for a new SCLP request
 * @ftp: pointer to FTP descriptor
 *
 * Return: 0 on success, else a (negative) error code.
 */
static int sclp_ftp_prepare(const struct hmcdrv_ftp_cmdspec *ftp)
{
	size_t len;

	struct sclp_diag_ftp *diag = &sclp_ftp_sccb->evbuf.mdd.ftp;

	diag->ldflg = SCLP_DIAG_FTP_LDFAIL;
	diag->fsize = 0;
	diag->cmd = ftp->id;
	diag->offset = ftp->ofs;
	diag->length = ftp->len;
	diag->bufaddr = virt_to_phys(ftp->buf);
	sclp_ftp_sccb->evbuf.hdr.flags = 0; /* clear "processed-buffer" */

	len = strlcpy(diag->fident, ftp->fname, HMCDRV_FTP_FIDENT_MAX);

	if (len >= HMCDRV_FTP_FIDENT_MAX)
		return -EINVAL;

	return 0;
}

/**
 * sclp_ftp_trigger() - prepare the SCCB and start a Diagnostic Test (ET7)
 * FTP Service SCLP request
 * @ftp: pointer to FTP descriptor
 *
 * Return: 0 on success, else a (negative) error code
 */
static int sclp_ftp_trigger(const struct hmcdrv_ftp_cmdspec *ftp)
{
	int rc = sclp_ftp_prepare(ftp);

	if (rc)
		return rc;

	sclp_ftp_status = SCLP_REQ_FILLED;
#ifdef DEBUG
	sclp_ftp_jiffies = jiffies;
#endif
	return sclp_ftp_et7(&sclp_ftp_requ);
}

/**
 * sclp_ftp_wait() - wait for a SCLP event from ISR, with timeout
 *
 * Return: 0 on success, else a (negative) error code
 */
static int sclp_ftp_wait(void)
{
	int rc;

	rc = wait_event_interruptible_timeout(
		sclp_ftp_waitq,
		sclp_ftp_status >= SCLP_REQ_DONE,
		HZ * SCLP_FTP_TIMEOUT);

	if (rc < 0)
		return rc; /* error (normally -ERESTARTSYS) */

	if (sclp_ftp_status < SCLP_REQ_DONE) {
		pr_warn("SCLP (ET7) with timeout, after %d seconds\n",
			SCLP_FTP_TIMEOUT);
		return -EIO; /* map internal timeout to EIO */
	}

#ifdef DEBUG
	pr_debug("completed SCLP (ET7) request after %lu ms (all), %d ms (rx)\n",
		 (jiffies - sclp_ftp_jiffies) * 1000 / HZ,
		 (HZ * SCLP_FTP_TIMEOUT - rc) * 1000 / HZ);
#endif
	return 0; /* no timeout, no error */
}

/**
 * sclp_ftp_cmd() - executes a HMC related SCLP Diagnose (ET7) FTP command
 * @ftp: pointer to FTP command specification
 * @fsize: return of file size (or NULL if undesirable)
 *
 * Attention: Notice that this function is not reentrant - so the caller
 * must ensure locking.
 *
 * Return: number of bytes read/written or a (negative) error code
 */
ssize_t sclp_ftp_cmd(const struct hmcdrv_ftp_cmdspec *ftp, size_t *fsize)
{
	ssize_t len;
	int rc;

	pr_debug("starting SCLP (ET7), cmd %d for '%s' at %lld with %zd bytes\n",
		 ftp->id, ftp->fname, (long long) ftp->ofs, ftp->len);

	rc = sclp_ftp_trigger(ftp);

	if (rc)
		return rc;

	/* First wait for end of request processing, then for an
	 * asynchronous event indicating the transfer has completed.
	 */
	if (wait_event_interruptible(sclp_ftp_waitq,
				     sclp_ftp_status >= SCLP_REQ_DONE))
		return -ERESTARTSYS;

	pr_debug("status of SCLP (ET7) request is 0x%04x (0x%02x, %d)\n",
		 sclp_ftp_sccb->hdr.response_code,
		 sclp_ftp_sccb->evbuf.hdr.flags,
		 sclp_ftp_status);

	rc = sclp_ftp_wait(); /* wait (with timeout) for RX event */

	pr_debug("return code of SCLP (ET7) FTP Service is 0x%02x (%d), with %lld/%lld bytes\n",
		 sclp_ftp_sccb->evbuf.mdd.ftp.ldflg,
		 sclp_ftp_status,
		 sclp_ftp_sccb->evbuf.mdd.ftp.length,
		 sclp_ftp_sccb->evbuf.mdd.ftp.fsize);

	if (rc)
		return rc;

	if (sclp_ftp_status != SCLP_REQ_DONE)
		return -EIO;

	switch (sclp_ftp_sccb->evbuf.mdd.ftp.ldflg) {
	case SCLP_DIAG_FTP_OK:
		len = sclp_ftp_sccb->evbuf.mdd.ftp.length;

		if (fsize)
			*fsize = sclp_ftp_sccb->evbuf.mdd.ftp.fsize;
		break;
	case SCLP_DIAG_FTP_LDNPERM:
		len = -EPERM;
		break;
	case SCLP_DIAG_FTP_LDRUNS:
		len = -EBUSY;
		break;
	case SCLP_DIAG_FTP_LDFAIL:
		len = -ENOENT;
		break;
	default:
		len = -EIO;
		break;
	}

	return len;
}

/**
 * sclp_ftp_startup() - startup of FTP services, when running on LPAR
 */
int sclp_ftp_startup(void)
{
	int rc;

#ifdef DEBUG
	unsigned long info;
#endif
	sclp_ftp_sccb = (struct sclp_diag_sccb *)
		get_zeroed_page(GFP_KERNEL | GFP_DMA);

	if (!sclp_ftp_sccb)
		return -ENOMEM;

	sclp_ftp_sccb->evbuf.hdr.type = EVTYP_DIAG_TEST;
	sclp_ftp_sccb->evbuf.hdr.length = SCLP_DIAG_FTP_EVBUF_LEN;
	sclp_ftp_sccb->evbuf.route = SCLP_DIAG_FTP_ROUTE;
	sclp_ftp_sccb->evbuf.mdd.ftp.pcx = SCLP_DIAG_FTP_XPCX;
	sclp_ftp_sccb->evbuf.mdd.ftp.srcflg = 0;
	sclp_ftp_sccb->evbuf.mdd.ftp.pgsize = 0;
	sclp_ftp_sccb->evbuf.mdd.ftp.asce = _ASCE_REAL_SPACE;
	sclp_ftp_sccb->hdr.length = SCLP_DIAG_FTP_EVBUF_LEN +
		sizeof(struct sccb_header);
	sclp_ftp_requ.sccb = sclp_ftp_sccb;
	rc = sclp_register(&sclp_ftp_event);

	if (rc) {
		free_page((unsigned long)sclp_ftp_sccb);
		sclp_ftp_sccb = NULL;
		return rc;
	}

#ifdef DEBUG
	info = get_zeroed_page(GFP_KERNEL);

	if (info != 0) {
		struct sysinfo_2_2_2 *info222 = (struct sysinfo_2_2_2 *)info;

		if (!stsi(info222, 2, 2, 2)) { /* get SYSIB 2.2.2 */
			info222->name[sizeof(info222->name) - 1] = '\0';
			EBCASC_500(info222->name, sizeof(info222->name) - 1);
			pr_debug("SCLP (ET7) FTP Service working on LPAR %u (%s)\n",
				 info222->lpar_number, info222->name);
		}

		free_page(info);
	}
#endif	/* DEBUG */
	return 0;
}

/**
 * sclp_ftp_shutdown() - shutdown of FTP services, when running on LPAR
 */
void sclp_ftp_shutdown(void)
{
	sclp_unregister(&sclp_ftp_event);
	free_page((unsigned long)sclp_ftp_sccb);
	sclp_ftp_sccb = NULL;
}
