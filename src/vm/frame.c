#include "frame.h"
#include "threads/vaddr.h"
#include "threads/pte.h"

struct list frame_table;

struct frame *
make_frame(void *addr)
{
    struct frame *fr = malloc(sizeof(struct frame));
    if (fr != NULL) {
        fr->addr = addr;
        //fr->pte = pte;
    }
    return fr;
}

void
set_frame(struct frame *fr, uint32_t *pte)
{
    fr->pte = pte;
}

void
frame_table_init(void)
{
    list_init(&frame_table);
}

void *
frame_alloc(bool zero)
{
    void *kaddr = palloc_get_page(PAL_USER | (zero ? PAL_ZERO : 0));
    if (!kaddr) {
		void *evicted_addr = frame_evict();
		swap_out(&evicted_addr);
		frame_free(&evicted_addr);
		kaddr = evicted_addr;
	}
	struct frame *new_fr = make_frame(vtop(kaddr));
    list_push_back(&frame_table, &new_fr->elem);
    return kaddr;
}

struct frame *
frame_find(void *kaddr)
{
    struct list_elem *e;
    for (e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e))
    {
        struct frame *fr = list_entry(e, struct frame, elem);
        if (fr->addr == kaddr) {
            return fr;
        }
        
    }
    return NULL;
}

void 
frame_free(void *kaddr)
{
    palloc_free_page(kaddr);

    struct frame *fr_to_free = frame_find(vtop(kaddr));

    //printf("here?");
    list_remove(&fr_to_free->elem);
    //printf("remove success");
    free(fr_to_free);
}

void *
frame_evict() 
{
	struct list_elem *e;
	void * kaddr;
	while (!list_empty(&frame_table)) {
		e = list_pop_front(&frame_table);
		struct frame *fr = list_entry(e, struct frame, elem);
		printf(fr->pte != NULL);
		if (fr->pte != NULL && (*(fr->pte) & PTE_D) != 0) {
			*(fr->pte) |=  PTE_D;
			list_push_back(&frame_table, e);
		} else if (fr->pte != NULL && (*fr->pte & PTE_A) != 0) {
			*(fr->pte) |= PTE_A;
			list_push_back(&frame_table, e);
		} else {
			kaddr = ptov(fr->addr);
			break;
		}
	}
	return kaddr; 
}

//Keep track of user pages.. later we'll use frame table to set a policy to evict frames and install new frame though pool is full!
