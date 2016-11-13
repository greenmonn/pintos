#ifndef VM_SWAP_H
#define VM_SWAP_H

/*Implementation of Swap Table*/

#include "devices/disk.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include <bitmap.h>

#define SWAP_FREE 0
#define SWAP_IN_USE 1

void swap_init (void);
size_t swap_out (void *frame);
void swap_in (size_t used_slot, void *frame);
void swap_free (size_t used_slot);
#endif
