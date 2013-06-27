#ifndef _HW_IRQ_H
#define _HW_IRQ_H

#include <linux/msi.h>
#include <linux/pci.h>

/* Interrupt handlers registered during init_IRQ */
irqreturn_t do_airq_interrupt(int irq, void *dummy);
irqreturn_t do_cio_interrupt(int irq, void *dummy);
irqreturn_t do_ext_interrupt(int irq, void *dummy);

void __init init_airq_interrupts(void);
void __init init_cio_interrupts(void);
void __init init_ext_interrupts(void);

#endif
