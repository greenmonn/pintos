#include "swap.h"

void swap_init(void) {
	swap_disk = disk_get(1,1);
	swap_table = bitmap_create (disk_size(swap_disk)*DISK_SECTOR_SIZE/PGSIZE);
	bitmap_set_all(swap_table,SWAP_FREE);
	lock_init(&swap_lock);
}

void swap_out (void* frame) {
	lock_acquire(&swap_lock);
	size_t free_slot = bitmap_scan_and_flip(swap_table, 0, 1, SWAP_FREE);
	
	ASSERT (free_slot != BITMAP_ERROR);

	for (size_t i = 0; i<PGSIZE/DISK_SECTOR_SIZE; i++) {
		disk_write(swap_disk,free_slot*PGSIZE/DISK_SECTOR_SIZE+i,(uint8_t *)frame+i*DISK_SECTOR_SIZE);
	} 
	lock_release(&swap_lock);

	return free_swap_slot;
}

void swap_in (size_t used_slot, void* frame) {
	lock_acquire(&swap_lock);
	ASSERT (used_slot<disk_size(swap_disk)*DISK_SECTOR_SIZE/PGSIZE);
	ASSERT (bitmap_test(swap_table,used_slot) == SWAP_IN_USED);

	bitmap_flip(swap_table,used_slot);


	for (size_t i =0; i<PGSIZE_DISK_SECTOR_SIZE; i++) {
		disk_read(swap_disk, used_slot*PGSIZE_DISK_SECTOR_SIZE+i,(uint8_t *)frame+i*DISK_SECTOR_SIZE);
	}
	lock_release(&swap_lock);
}
