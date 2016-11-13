#ifndef VM_FRAME_H
#define VM_FRAME_H

/* Implementation of Frame Table
 * Method for Frame Allocation / Eviction Policy? */
#include "threads/thread.h"
#include "threads/palloc.h"
#include <stdio.h>
#include <list.h>

struct frame
{
    struct list_elem elem;
    void *addr; //physical memory address
    uint32_t *pte;
    void *upage; //Installed page's User virtual address
    struct thread *owner;
    bool pin;

};

struct frame *make_frame(void *addr, struct thread *owner);
void set_frame(struct frame *fr, uint32_t *pte);
void frame_table_init(void);
void * frame_alloc(bool zero);
void frame_free();
struct frame * frame_evict();

#endif /* vm/frame.h */
