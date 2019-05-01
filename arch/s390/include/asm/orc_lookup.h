#ifndef _ORC_LOOKUP_H
#define _ORC_LOOKUP_H

/*
 * This is a lookup table for speeding up access to the .orc_unwind table.
 * Given an input address offset, the corresponding lookup table entry
 * specifies a subset of the .orc_unwind table to search.
 *
 * Each block represents the end of the previous range and the start of the
 * next range. An extra block is added to give the last range an end.
 *
 * The block size should be a power of 2 to avoid a costly 'div' instruction.
 *
 * A test kernel build from 5.0-rc5 with the performance_defconfig
 * resulted in 9781248 bytes between _stext and _etext. The two orc tables
 * .orc_unwind and .orc_unwind_ip had 120680 entries, with different values
 * for LOOKUP_BLOCK_ORDER .orc_lookup table came out like this:
 *   block order 8: avg search bucket size 3.15, max size 24
 *   block order 9: avg search bucket size 6.32, max size 36
 *   block order 10: avg search bucket size 12.63, max size 52
 * A good choice seems to be a LOOKUP_BLOCK_ORDER of 9, that increases the
 * ORC data footprint by ~75KB or ~8%.
 */

#define LOOKUP_BLOCK_ORDER	9
#define LOOKUP_BLOCK_SIZE	(1 << LOOKUP_BLOCK_ORDER)

#ifndef LINKER_SCRIPT

extern unsigned int orc_lookup[];
extern unsigned int orc_lookup_end[];

#define LOOKUP_START_IP		(unsigned long)_stext
#define LOOKUP_STOP_IP		(unsigned long)_etext

#endif /* LINKER_SCRIPT */

#endif /* _ORC_LOOKUP_H */
