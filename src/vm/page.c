/* page.c */

#include "page.h"
#include "swap.h"
#include "frame.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/pte.h"
//#include "userprog/syscall.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include <stdio.h>
#include <string.h>

#define STACK_SIZE 262144

/* Create a new "page", which saves information for later installation of physical memory frame. */
struct page *
make_page(void *uaddr, enum page_location place)
{
    struct page *pg = malloc(sizeof (struct page)); //ASSERT: kernel pool?
        pg->uaddr = uaddr;
        pg->location = place;
        //pg->is_code_seg = false;
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
	return true;
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
        frame_free(pg->fr);
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
install_page (struct page *pg, struct frame *fr, bool writable)
{
    struct thread *t = thread_current();

    //1. Save upage to the frame
    //struct frame *fr = frame_find(kpage);
    void *kpage = ptov(fr->addr);
    //ASSERT(fr != NULL);
        fr->upage = pg->uaddr;
        //fr->pin = false; WE'll do it in pagedir_set_page
    //ASSERT(fr != NULL);
    //2. Save writable value to the page
        pg->writable = writable;
        pg->fr = fr;


    return (pagedir_get_page (t->pagedir, pg->uaddr) == NULL
            && pagedir_set_page (t->pagedir, pg->uaddr, kpage, writable));
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
                kpage = ptov(newfr->addr);
                //memset (kpage, 0, PGSIZE);
                install_page (pg, newfr, pg->writable);
				pg->location = FRAME;
                pagedir_set_accessed(t->pagedir, upage, true);
                //pagedir_set_dirty(t->pagedir, upage, false);
                //newfr = frame_find(kpage);
                //newfr->pin = false;
                return 1;
                break; //Never reached
            case SWAP:
                newfr = frame_alloc(false);
                kpage = ptov(newfr->addr);
                swap_in(pg->swap_index, kpage);
                //printf("1\n");
                pg->location = FRAME;
                //pg->swap_index = -1;
                install_page(pg, newfr, pg->writable);
               
                //pagedir_set_dirty(t->pagedir, upage, true);
                pagedir_set_accessed(t->pagedir, upage, true);
                //newfr = frame_find(kpage);
                //newfr->pin = false;
                return 1;
                break;
            case FRAME:
                //printf("frame\n");
                return 0;
                break;
            case FILE: //Lazy Loading!

                newfr = frame_alloc(false);
                kpage = ptov(newfr->addr);
                page_read_bytes = pg->page_read_bytes;
                page_zero_bytes = PGSIZE - page_read_bytes;
                filesys_lock_acquire();
                if (file_read_at(pg->file, kpage, page_read_bytes,pg->ofs) != (int) page_read_bytes) {
                    frame_free(newfr);
                    filesys_lock_release();
                    printf("file_read fail\n");
                    return 0;
                }

                memset (kpage + page_read_bytes, 0, page_zero_bytes);

                filesys_lock_release();

                install_page (pg, newfr, pg->writable);
                pg->location = FRAME;

                pagedir_set_accessed(t->pagedir, upage, true);
                //pagedir_set_dirty(t->pagedir, upage, false);
                //newfr->pin = false;
                return 1;

                break;
            case MMAP:

                newfr = frame_alloc(false);
                kpage = ptov(newfr->addr);
                if (kpage == NULL) {
                    printf("frame_alloc fail : should PANIC\n");
                    return 0;
                }
                page_read_bytes = pg->page_read_bytes;
                page_zero_bytes = PGSIZE - page_read_bytes;


                filesys_lock_acquire();
                if (file_read_at(pg->file, kpage, page_read_bytes,pg->ofs) != (int) page_read_bytes) {
                    frame_free(newfr);
                    filesys_lock_release();
                    printf("file_read fail\n");
                    return 0;
                }

                memset (kpage + page_read_bytes, 0, page_zero_bytes);


                filesys_lock_release();
                install_page (pg, newfr, pg->writable);
                      
				pg->location = MMAP;

                pagedir_set_accessed(t->pagedir, upage, true);
                //pagedir_set_dirty(t->pagedir, upage, false);
                //newfr->pin = false;
                return 1;

                break;

            default:
                break;
        }
    } 
    else {
        void *esp = thread_current()->esp;
    	//printf("stack_grow\n");
      
        if ((size_t)esp - 32 > ((size_t)fault_addr) || ((size_t)PHYS_BASE) - ((size_t)((void *)fault_addr)) > STACK_SIZE) {
            //printf("pg is null\n");
            
            return 0;
        }

        newfr = frame_alloc(true);

        kpage = ptov(newfr->addr);

        /*if (kpage != NULL) {*/
            struct page *stk_pg = make_page(upage, FRAME);
            //stk_pg->file = NULL;
            /*if (stk_pg == NULL) {
                frame_free(kpage);
                return 0;
            }*/
            page_insert(pages, stk_pg);
           	install_page(stk_pg, newfr, true);
			pagedir_set_accessed(thread_current()->pagedir, upage, true);

        //newfr->pin = false;
            //pagedir_set_dirty(t->pagedir, upage, false);

			return 1;
        //    }
        /*else {
            frame_free(kpage);
            return 0;
        }*/

        //return 0;

    }
}





