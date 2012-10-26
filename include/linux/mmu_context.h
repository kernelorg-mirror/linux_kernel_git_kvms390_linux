#ifndef _LINUX_MMU_CONTEXT_H
#define _LINUX_MMU_CONTEXT_H

#include <asm/mmu_context.h>

struct mm_struct;

void use_mm(struct mm_struct *mm);
void unuse_mm(struct mm_struct *mm);

#ifndef finish_switch_mm
#define finish_switch_mm(mm, tsk) do { } while (0)
#endif

#endif
