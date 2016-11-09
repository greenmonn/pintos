/* page.c */

#include "page.h"
#include "threads/thread.h"
#include "threads/malloc.h"
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
    page_->is_code_seg = false;
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
    hash_insert(pages, &page->elem);
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
install_page (void *upage, void *kpage, bool writable)
{
    struct thread *t = thread_current();

    //printf("upage already installed to %x\n", pagedir_get_page(t->pagedir, upage));
    //printf("upage : %x\n", upage);

    return (pagedir_get_page (t->pagedir, upage) == NULL
            && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

int
install_suppl_page(struct hash *pages, struct page *pg, void *upage)
{
    uint8_t *kpage;
    size_t page_read_bytes;
    size_t page_zero_bytes;
    //printf("install_suppl_page\n");
    if (pg != NULL) {
        switch(pg->location) {
            case ZERO:
                kpage = frame_alloc(true);
                if (kpage == NULL) {
                    //exit(-1);
                    return 0;
                }
                //memset (kpage, 0, PGSIZE);
                if (!install_page (upage, kpage, pg->writable))
                {
                    frame_free(kpage);
                    //exit(-1);
                    return 0;
                }
                return 1;
                break; //Never reached
            case SWAP:
                break;
            case FRAME:
                break;
            case FILE: //Lazy Loading!
                //printf("filesys_lock\n");
                filesys_lock_acquire();
                //printf("lock after\n");
                kpage = frame_alloc(false);
                //printf("1");
                if (kpage == NULL) {
                    return 0;
                    //exit(-1);
                }
                //printf("2");
                page_read_bytes = pg->page_read_bytes;
                page_zero_bytes = PGSIZE - page_read_bytes;


                file_seek(pg->file, pg->ofs);
                if (file_read (pg->file, kpage, page_read_bytes) != (int) page_read_bytes) {
                    frame_free(kpage);
                    filesys_lock_release();
                    return 0;
                    //exit(-1);
                }
                //printf("3");
                memset (kpage + page_read_bytes, 0, page_zero_bytes);
                //printf("filesys_lock_release\n");
                filesys_lock_release();
                //printf("after release\n");

                if (!install_page (upage, kpage, pg->writable))
                {
                    //printf("install page fail?\n");
                    frame_free(kpage);
                    return 0;
                    //exit(-1);
                }
                //printf("4");

                return 1;
                break;
            default:
                break;
        }
    }
    else {
        return 0;
        //exit(-1);
    }
}



