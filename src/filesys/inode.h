#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/disk.h"
#include "threads/thread.h"
#include <list.h>

struct inode_disk 
{
	off_t length;
	unsigned magic;

	disk_sector_t direct_idx[9];
	disk_sector_t indirect_idx[4];
	disk_sector_t double_indirect_idx;
    
    /* used if directory */
	bool is_dir;
    disk_sector_t parent;

	uint32_t unused[110];
};

struct inode_data
{
    off_t length;
    unsigned magic;
    disk_sector_t direct_idx[9];
    disk_sector_t indirect_idx[4];
    disk_sector_t double_indirect_idx;
    bool is_dir;
    disk_sector_t parent;
};


struct inode
{
	struct list_elem elem;
	disk_sector_t sector;
	int open_cnt;

    /* Reading Thread should wait for writing thread to finish up */
    //struct semaphore sema;
    //bool writing_cnt;
	
    bool removed;
	int deny_write_cnt;
	struct inode_data data;

    struct lock lock;
};

struct bitmap;

void inode_init (void);
bool inode_create (disk_sector_t, off_t, bool is_dir);
struct inode *inode_open (disk_sector_t);
struct inode *inode_reopen (struct inode *);
disk_sector_t inode_get_inumber (const struct inode *);
void inode_close (struct inode *);
void inode_remove (struct inode *);
off_t inode_read_at (struct inode *, void *, off_t size, off_t offset);
off_t inode_write_at (struct inode *, const void *, off_t size, off_t offset);
void inode_deny_write (struct inode *);
void inode_allow_write (struct inode *);
off_t inode_length (const struct inode *);

#endif /* filesys/inode.h */
