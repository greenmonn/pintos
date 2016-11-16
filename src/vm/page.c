/* page.c */

#include "page.h"
#include "swap.h"
#include "frame.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/pte.h"
#include "userprog/syscall.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include <stdio.h>
#include <string.h>

/* Create a new "page", which saves information for later installation of physical memory frame. */
struct page *
make_page(void *uaddr, enum page_location place)
{
    struct page *pg = malloc(sizeof (struct page)); //ASSERT: kernel pool?
    if (pg != NULL) {
        pg->uaddr = uaddr;
        pg->location = place;
        //pg->is_code_seg = false;
    }
    return pg;
}

/* 1. page type : FILE */

void
page_set_file(struct hash *pages, struct page *page_, struct file *file_,int32_t ofs_, bool writable_, int page_read_bytes_)
{
    page_insert(pages, page_);
    page_->file = file_;
    page_->ofs = ofs_;
    page_->writable = writable_;
    page_->page_read_bytes = page_read_bytes_;
    //page_->is_code_seg = false;
}
// Later we'll get frame and read the file then install to the physical memory.


/* 2. page type : SWAP */

//TODO


/* Create a new supplemental "page table", which is maintained by each process */

struct hash *
suppl_pages_create (void)
{
    struct hash *pages = malloc(sizeof (struct hash));
    hash_init(pages, page_hash, page_less, NULL);
    return pages;
}

static void page_free_func (struct hash_elem *e, void *aux UNUSED)
{
    struct page *pg = hash_entry(e, struct page, elem);
    if (pg->location == FRAME)
    {
        frame_free(pagedir_get_page(thread_current()->pagedir, pg->uaddr));
        pagedir_clear_page(thread_current()->pagedir, pg->uaddr);
    } else if (pg->location == SWAP) {
		swap_free(pg->swap_index);
	}
    free(pg);
}

void
suppl_pages_destroy (struct hash * pages) 
{
    //printf("suppl_pages_destroy\n");
    hash_destroy(pages, page_free_func);
    //printf("suppl_pages_destroy end\n");
}

/* Functions for Hashing. */

unsigned 
page_hash(const struct hash_elem *p_, void *aux UNUSED)
{
    const struct page *p = hash_entry(p_, struct page, elem);
    return hash_bytes(&p->uaddr, sizeof p->uaddr);
}

bool
page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED)
{
    const struct page *a = hash_entry (a_, struct page, elem);
    const struct page *b = hash_entry (b_, struct page, elem);

    return a->uaddr < b->uaddr;
}

void
page_insert(struct hash *pages, struct page *page)
{
    hash_replace(pages, &page->elem);
    //not allow duplication!
}

/* Returns the page containing the given virtual address,
 * or a null pointer if no such page exists */
struct page *
page_lookup(struct hash *pages, const void *addr)
{
    struct page p;
    struct hash_elem *e;

    p.uaddr = addr;
    e = hash_find(pages, &p.elem);
    return e != NULL ? hash_entry (e, struct page, elem) : NULL;
}

bool
install_page (void *upage, struct frame *fr, bool writable)
{
    struct thread *t = thread_current();

    //1. Save upage to the frame
    //struct frame *fr = frame_find(kpage);
    void *kpage = ptov(fr->addr);
    //ASSERT(fr != NULL);
    if (fr != NULL) { 
        fr->upage = upage;
        //fr->pin = false; WE'll do it in pagedir_set_page
    }
    ASSERT(fr != NULL);
    //2. Save writable value to the page
    struct page *pg = page_lookup(t->suppl_pages, upage);
    if (pg != NULL) {
        pg->writable = writable;
    }


    return (pagedir_get_page (t->pagedir, upage) == NULL
            && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

int
install_suppl_page(struct hash *pages, struct page *pg, void *fault_addr) 
{
    uint8_t *kpage;
    void *upage = pg_round_down(fault_addr);
    size_t page_read_bytes;
    size_t page_zero_bytes;
    struct frame *newfr;
    struct thread *t = thread_current();
    //printf("install_suppl_page : %x\n", fault_addr);
    if (pg != NULL) {
        switch(pg->location) {
            case ZERO:
                newfr = frame_alloc(true);
                if (newfr == NULL) {
                    return 0;
                }
                kpage = ptov(newfr->addr);
                //memset (kpage, 0, PGSIZE);
                if (!install_page (upage, newfr, pg->writable))
                {
                    frame_free(kpage);
                    printf("install page fail\n");
                    return 0;
                }
                pg->location = FRAME;
                pagedir_set_accessed(t->pagedir, upage, true);
                pagedir_set_dirty(t->pagedir, upage, false);
                //newfr = frame_find(kpage);
                newfr->pin = false;
                return 1;
                break; //Never reached
            case SWAP:
				newfr = frame_alloc(false);
				if (newfr == NULL) return 0;
                kpage = ptov(newfr->addr);
				swap_in(pg->swap_index, kpage);
				pg->location = FRAME;
				pg->swap_index = -1;
				if (!install_page(upage, newfr, pg->writable))
				{
					frame_free(kpage);
					return 0;
				}

                pagedir_set_dirty(t->pagedir, upage, true);
                pagedir_set_accessed(t->pagedir, upage, true);
                //newfr = frame_find(kpage);
                newfr->pin = false;
				return 1;
                break;
            case FRAME:
                return 0;
                break;
            case FILE: //Lazy Loading!

                newfr = frame_alloc(false);
                kpage = ptov(newfr->addr);
                if (kpage == NULL) {
                    printf("frame_alloc fail : should PANIC\n");
                    return 0;
                }
                page_read_bytes = pg->page_read_bytes;
                page_zero_bytes = PGSIZE - page_read_bytes;


                filesys_lock_acquire();
                file_seek(pg->file, pg->ofs);
                if (file_read (pg->file, kpage, page_read_bytes) != (int) page_read_bytes) {
                    frame_free(kpage);
                    filesys_lock_release();
                    printf("file_read fail\n");
                    return 0;
                }
                filesys_lock_release();
                memset (kpage + page_read_bytes, 0, page_zero_bytes);

                
                if (!install_page (upage, newfr, pg->writable))
                {
                    frame_free(kpage);
                    printf("install page fail\n");
                    return 0;
                }
				pg->location = FRAME;

                pagedir_set_accessed(t->pagedir, upage, true);
                pagedir_set_dirty(t->pagedir, upage, false);
                newfr->pin = false;
                return 1;

                break;
            default:
                break;
        }
    }
    else {
        void *esp = thread_current()->esp;

        //printf("Faulted page %x has no SUPP PAGE\n", upage);
        if (esp - 32 > fault_addr)
            return 0;

        //it's stack access!
        uint8_t *stack_end = upage;
        if (upage < stack_end)
            stack_end = upage;
        if (stack_end < PHYS_BASE - 32 * 1024 * 1024)
            return 0;   //grow too much!

        int i = 0;
        int success = 1;
        while (success) {
            struct frame *newfr = frame_alloc(true);
            kpage = ptov(newfr->addr);

            if (kpage != NULL) {
                struct page *stk_pg = make_page(stack_end + PGSIZE * i, FRAME);
                page_insert(thread_current()->suppl_pages, stk_pg);
                success = install_page(stack_end + PGSIZE*i, newfr, true);

                pagedir_set_accessed(thread_current()->pagedir, stack_end + PGSIZE*i, true);
                pagedir_set_dirty(thread_current()->pagedir, stack_end + PGSIZE*i, true);
                newfr->pin = false;
                i++;
            }
            else {
                success = -1;
                break;
            }
        } //while finished

        if (success != -1) {
            frame_free(kpage);  //free install_failed frame!
            return 1;
        }

        return 0;   //Stack Growth Failed


    }
}



