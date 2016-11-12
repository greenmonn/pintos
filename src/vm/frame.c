#include "frame.h"
#include "swap.h"
#include "page.h"
#include "threads/vaddr.h"
#include "threads/pte.h"

struct list frame_table;
struct lock frame_lock;

struct frame *
make_frame(void *addr)
{
    struct frame *fr = malloc(sizeof(struct frame));
    if (fr != NULL) {
        fr->addr = addr;
        fr->pte = NULL;
        fr->upage = NULL;
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
    lock_init(&frame_lock);
}

struct frame *
frame_find(void *kaddr)
{
    struct list_elem *e;
    void *addr = vtop(kaddr);
    for (e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e))
    {
        struct frame *fr = list_entry(e, struct frame, elem);
        if (fr->addr == addr) {
            return fr;
        }
        
    }
    return NULL;
}
void *
frame_alloc(bool zero)
{	
    lock_acquire(&frame_lock);
    void *kaddr = palloc_get_page(PAL_USER | (zero ? PAL_ZERO : 0));
    if (!kaddr) {
		struct frame *evicted_fr = frame_evict();
        void *evicted_addr = ptov(evicted_fr->addr);


        printf("1\n");
		//struct frame * evicted_fr = frame_find(evicted_addr);
        printf("2\n");
		kaddr = evicted_addr;
		struct page * evicted_page = page_lookup(thread_current()->suppl_pages, evicted_fr->upage); //ERROR!!!! evicted_fr->pte is kernel virtual address.. how to find user address from frame?
        printf("3\n");

        printf("evicted page uaddr is, %x\n", pg_round_down(*(evicted_fr->pte)));
        printf("supp page : %x\n", evicted_page);
        printf("supp page is in %d\n", evicted_page->location);
		
		size_t swap_index = swap_out(evicted_addr);
        printf("evicted supp page : %x\n", evicted_page);
        printf("current location : %d\n", evicted_page->location);
        evicted_page->location = SWAP;
        evicted_page->swap_index = swap_index;
        evicted_page->writable =(*(evicted_fr->pte) & PTE_W) == 0 ? false : true;
        frame_free(evicted_addr);
    }
    struct frame *new_fr = make_frame(vtop(kaddr));
    list_push_back(&frame_table, &new_fr->elem);

    lock_release(&frame_lock);
    return kaddr;
}

void 
frame_free(void *kaddr) //delete frame from list + free the frame!
{
    palloc_free_page(kaddr);

    struct frame *fr_to_free = frame_find(kaddr);

    //printf("here?");
    list_remove(&fr_to_free->elem);
    //printf("remove success");
    free(fr_to_free);
}

struct frame *
frame_evict() 
{	
	struct list_elem *e;
	void * kaddr;
    struct frame *fr = NULL;
	while (!list_empty(&frame_table)) {
		e = list_pop_front(&frame_table);
		fr = list_entry(e, struct frame, elem);

		if (fr->pte != NULL && (*(fr->pte) & PTE_D) != 0) {
			*(fr->pte) &= ~PTE_D;
			list_push_back(&frame_table, e);
		} else if (fr->pte != NULL && (*(fr->pte) & PTE_A) != 0) {
			*(fr->pte) &= ~PTE_A;
			list_push_back(&frame_table, e);
		} else {
            if (fr->pte != NULL) {
			    kaddr = ptov(fr->addr);
                //list_push_back(&frame_table, e);
			    break;
            }
            else {
                list_push_back(&frame_table, e);
            }
		}
	}
    ASSERT(fr != NULL);
    printf("frame evicted : %x\n", kaddr);
	return fr; 
}

//Keep track of user pages.. later we'll use frame table to set a policy to evict frames and install new frame though pool is full!
