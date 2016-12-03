#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

/* Implement Buffer Cache */

//Shared by all processes
//Write-behind & Read-ahead policy
#include "threads/thread.h"
#include "threads/palloc.h"
#include "filesys/off_t.h"
#include "devices/disk.h"
#include <stdio.h>
#include <hash.h>

struct cache_entry
{
    struct hash_elem elem;
    disk_sector_t sector_no;
    bool used;
    bool dirty;
    void *data; //DISK_SECTOR_SIZE
};

struct hash buffer_cache;
struct lock cache_lock;

unsigned cache_hash(const struct hash_elem *p_, void *aux UNUSED);
bool cache_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);

void cache_init();

int read_in_cache(disk_sector_t sector_idx, int sector_ofs, void *buffer, int readsize);
int write_to_cache(disk_sector_t sector_idx, int sector_ofs, void *buffer, int length, bool partial);




#endif /* filesys/cache.h */

