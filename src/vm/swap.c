#include "swap.h"


#define SECTORS_IN_PG (PGSIZE/DISK_SECTOR_SIZE)

struct disk *swap_disk;
struct bitmap *swap_table;
struct lock swap_lock;

void swap_init(void) {
	swap_disk = disk_get(1,1);
    //SWAP TABLE : 1 bit = 1 page?
    //swap_table = bitmap_create (disk_size(swap_disk)*DISK_SECTOR_SIZE/PGSIZE);
	swap_table = bitmap_create (disk_size(swap_disk)/SECTORS_IN_PG);
	bitmap_set_all(swap_table,SWAP_FREE);
	lock_init(&swap_lock);
}

// We'll Swap in unit of ONE PAGE


/* MEMORY -> DISK */
size_t swap_out (void *frame) {
	lock_acquire(&swap_lock);
	size_t free_slot = bitmap_scan_and_flip(swap_table, 0, 1, SWAP_FREE);
	//ASSERT (free_slot != BITMAP_ERROR);

    size_t i;
	for (i = 0; i<SECTORS_IN_PG; i++) {
		disk_write(swap_disk, free_slot*SECTORS_IN_PG + i, (uint8_t *)frame + i*DISK_SECTOR_SIZE);
	} 
	lock_release(&swap_lock);

	return free_slot;
}

/* DISK -> MEMORY */
void swap_in (size_t used_slot, void *frame) {
    //printf("swap in\n");
	lock_acquire(&swap_lock);
	//ASSERT (used_slot < disk_size(swap_disk)/SECTORS_IN_PG);
	//ASSERT (bitmap_test(swap_table, used_slot) == SWAP_IN_USE);

	bitmap_flip(swap_table,used_slot);


    size_t i;
	for (i = 0; i<SECTORS_IN_PG; i++) {
		disk_read(swap_disk, used_slot*SECTORS_IN_PG + i, (uint8_t *)frame + i*DISK_SECTOR_SIZE);
	}
	lock_release(&swap_lock);
}

void swap_free (size_t used_slot) {
	lock_acquire(&swap_lock);
	bitmap_set_multiple(swap_table,used_slot,1, SWAP_FREE);
	lock_release(&swap_lock);
}
