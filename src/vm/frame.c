#include "frame.h"
#include "swap.h"
#include "page.h"
#include "threads/vaddr.h"
#include "threads/pte.h"

struct list frame_table;
struct lock frame_lock;

struct frame *
make_frame(void *addr, struct thread *owner)
{
    struct frame *fr = malloc(sizeof(struct frame));
    if (fr != NULL) {
        fr->addr = addr;
        fr->pte = NULL;
        fr->upage = NULL;
        fr->owner = owner;
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
            printf("find addr : %x\n", fr->addr);
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
    printf("pallod_get_page : %x\n", kaddr);
    if (!kaddr) {   //Evict a frame and make it as MINE!
		struct frame *evicted_fr = frame_evict();
        void *evicted_addr = ptov(evicted_fr->addr);


		struct page * evicted_page = page_lookup((evicted_fr->owner)->suppl_pages, evicted_fr->upage);
        //printf("3\n");

        printf("evicted physical addr is, %x\n", pg_round_down(*(evicted_fr->pte)));
        printf("evicted user addr is, %x\n", evicted_fr->upage);
        printf("supp page of evicted page : %x\n", evicted_page);
        printf("supp page is in %d\n", evicted_page->location);

       
    pagedir_clear_page((evicted_fr->owner)->pagedir, evicted_fr->upage);
		size_t swap_index = swap_out(evicted_addr);
        printf("evicted supp page : %x\n", evicted_page);
        printf("current location : %d\n", evicted_page->location);
        if(evicted_page != NULL) {

            evicted_page->location = SWAP;
            evicted_page->swap_index = swap_index;
            evicted_page->writable =(*(evicted_fr->pte) & PTE_W) == 0 ? false : true;
        } 
        else {
            struct page *new_swap_page = make_page(evicted_fr->upage, SWAP);
            new_swap_page->writable = (*(evicted_fr->pte) & PTE_W) == 0 ? false : true;
            new_swap_page->swap_index = swap_index;
            page_insert(thread_current()->suppl_pages, new_swap_page);
        }
        frame_free(evicted_addr);
        
        //REtry palloc!
        kaddr = palloc_get_page(PAL_USER | (zero ? PAL_ZERO : 0));
    }
    struct frame *new_fr = make_frame(vtop(kaddr), thread_current());
    printf("make_frame : %s\n", thread_current()->name);
    list_push_back(&frame_table, &new_fr->elem);

    lock_release(&frame_lock);
    return kaddr;
}

void 
frame_free(void *kaddr) //delete frame from list + free the frame!
{
    palloc_free_page(kaddr);

    struct frame *fr_to_free = frame_find(kaddr);
    //pagedir_clear_page(fr_to_free->owner->pagedir, fr_to_free->upage);
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
                list_push_back(&frame_table, e);
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
