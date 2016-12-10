#include "filesys/cache.h"
#include <debug.h>
#include <string.h>
#include "threads/malloc.h"
#include "threads/thread.h"
#include "filesys/filesys.h"
#include "devices/timer.h"



static thread_func read_ahead_thread;
static thread_func write_back_thread;

unsigned cache_hash (const struct hash_elem *p_, void *aux UNUSED)
{
    const struct cache_entry *p = hash_entry(p_, struct cache_entry, elem);
    return hash_bytes(&p->sector_no, sizeof (p->sector_no));
}

bool cache_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED)
{
    const struct cache_entry *a = hash_entry(a_, struct cache_entry, elem);
    const struct cache_entry *b = hash_entry(b_, struct cache_entry, elem);

    return a->sector_no < b->sector_no;
}

void cache_init () 
{
    hash_init(&buffer_cache, cache_hash, cache_less, NULL);
    lock_init(&cache_lock);
    thread_create("write-back", PRI_DEFAULT, write_back_thread, NULL);
}

struct cache_entry * cache_lookup(disk_sector_t sector_no)
{
    struct cache_entry c;
    struct hash_elem *e;

    c.sector_no = sector_no;
    e = hash_find(&buffer_cache, &c.elem);
    return e != NULL ? hash_entry (e, struct cache_entry, elem) : NULL;
}


//[TODO 1] read_in_cache : Cache hit - return data / Cache miss - insert new entry
//[TODO 2-1] cache_evict : if cache is full - evict one by clock algorithm

//[TODO 2-2] cache_insert : Insert a new cache entry(if Cache miss) handle evict inside
//[TODO 3] implement read-ahead policy
void cache_insert(struct cache_entry *new_entry)
{
    ASSERT(cache_lookup(new_entry->sector_no) == NULL);

    int currsize = hash_size(&buffer_cache);
    if (currsize < 64) {
        //printf("insert entry : %d\n", new_entry->sector_no);
        hash_insert(&buffer_cache, &new_entry->elem);
        return;
    }
    //printf("cache entry should be evicted!\n");
    cache_evict();
    hash_insert(&buffer_cache, &new_entry->elem);
}

void cache_evict() {    //LIMITATION : cannot save iterator
    struct hash_iterator i;
    hash_first (&i, &buffer_cache);
    while (true)
    {
        if (hash_next (&i) == NULL) {
            hash_first(&i, &buffer_cache);
            hash_next (&i);
        }

        struct cache_entry *ce = hash_entry (hash_cur (&i), struct cache_entry, elem);
        //printf("cache entry %d\n", ce->sector_no);
        if (ce->used == true)
            ce->used = false;
        else {  //Evict this entry!
            hash_delete(&buffer_cache, &ce->elem);
            if (ce->dirty == true) {
                disk_write(filesys_disk, ce->sector_no, ce->data);
            }
            //printf("evicted %d\n", ce->sector_no);
            free(ce->data);
            free(ce);
            return;
        }

    }
}
int read_in_cache(disk_sector_t sector_idx, int sector_ofs, void *buffer, int readsize)
{
    //printf("File Read : %d\n", sector_idx);
    lock_acquire(&cache_lock);
    struct cache_entry *ce = cache_lookup(sector_idx);
    if (ce != NULL) {
        /* Cache hit */
         memcpy(buffer, ce->data + sector_ofs, readsize);
         ce->used = true;
         lock_release(&cache_lock);
         return readsize;
    }

    /* Cache miss */
    // 1. Make a new cache_entry
    struct cache_entry *new_entry = malloc(sizeof (struct cache_entry));
    new_entry->sector_no = sector_idx;
    new_entry->used = true;
    new_entry->dirty = false;
    new_entry->data = malloc(DISK_SECTOR_SIZE); //Kernel pool?
    cache_insert(new_entry);


    // 2. read data from disk
    disk_sector_t *aux = malloc(sizeof(disk_sector_t));
    *aux = sector_idx + 1;
    
    //printf("thread_create for read-ahead\n");
    //thread_create("read-ahead", PRI_DEFAULT, read_ahead_thread, (void*)aux);
    disk_read(filesys_disk, sector_idx, new_entry->data);
    // 3. copy to buffer by readsize
    memcpy(buffer, new_entry->data + sector_ofs, readsize);

    lock_release(&cache_lock);
    return readsize;  

}

static void
read_ahead_thread (void *aux)
{
    disk_sector_t sector_no = *(disk_sector_t *)aux;
    //printf("read_ahead thread : %d\n", sector_no);
    lock_acquire(&cache_lock);
    struct cache_entry *ce = cache_lookup(sector_no);
    if (ce != NULL) {
        free(aux);
        lock_release(&cache_lock);
        return;
    }
    struct cache_entry *new_entry = malloc(sizeof (struct cache_entry));
    new_entry->sector_no = sector_no;
    new_entry->used = true;
    new_entry->dirty = false;
    new_entry->data = malloc(DISK_SECTOR_SIZE);
    cache_insert(new_entry);


    disk_read(filesys_disk, sector_no, new_entry->data);
    lock_release(&cache_lock);

    free(aux);
}

static void
write_back_thread (void *aux UNUSED)
{
    while (true)
    {
        timer_sleep(5*TIMER_FREQ);
        //printf("Write back time!\n");
        lock_acquire(&cache_lock);
        struct hash_iterator i;
        hash_first (&i, &buffer_cache);
        while (hash_next(&i))
        {
           struct cache_entry *ce = hash_entry (hash_cur (&i), struct cache_entry, elem);
           if (ce->dirty == true) {
               disk_write(filesys_disk, ce->sector_no, ce->data);
               ce->dirty = false;
           }
        }
        lock_release(&cache_lock); 
    }
}
//[TODO 4] write_to_cache : Cache hit - modify data / Cache miss - insert new entry to cache

int write_to_cache(disk_sector_t sector_idx, int sector_ofs, void *buffer, int length, bool partial)
{
    //printf("File write : %d\n", sector_idx);
    lock_acquire(&cache_lock);
    struct cache_entry *ce = cache_lookup(sector_idx);
    if (ce != NULL) {
        /* Cache hit */
        //No difference between partial copy and full
        memcpy(ce->data + sector_ofs, buffer, length);
        ce->used = true;
        ce->dirty = true;
        lock_release(&cache_lock);
        return length;
    }

    /* Cache miss */
    // 1. Make a new cache_entry
    struct cache_entry *new_entry = malloc(sizeof (struct cache_entry));
    new_entry->sector_no = sector_idx;
    new_entry->used = true;
    new_entry->dirty = true;
    new_entry->data = malloc(DISK_SECTOR_SIZE);
    cache_insert(new_entry);




    //2. Write to cache
    if (partial)
        disk_read(filesys_disk, sector_idx, new_entry->data);
    else
        memset(new_entry->data, 0, DISK_SECTOR_SIZE);
        
    memcpy(new_entry->data + sector_ofs, buffer, length);

    lock_release(&cache_lock);
    return length;
}

//[TODO 5] update_write : Periodically update dirty blocks to the real disk- using timer_sleep() (Later)
