#ifndef VM_PAGE_H
#define VM_PAGE_H

/* Implementation of Supplemental Page Table
 * Methods for Paging / Lazy Loading? */
#include "threads/thread.h"
#include <stdio.h>
#include <hash.h>

enum page_location
{
    FRAME,
    SWAP,
    FILE,
    ZERO
};

struct page
{
    struct hash_elem elem;
    void *uaddr; //hash key
    enum page_location location;
    struct file *file;
    bool writable;
    bool is_code_seg;
    int32_t ofs;
    int page_read_bytes;
	size_t swap_index;
};

struct page *make_page(void *uaddr, enum page_location location);

void page_set_file(struct hash *pages, struct page *pg, struct file *f, int32_t ofs, bool writable, int page_read_bytes);

struct hash * suppl_pages_create(void);
unsigned page_hash(const struct hash_elem *p, void *aux UNUSED);

bool page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);

void page_insert(struct hash *pages, struct page *page);

struct page *page_lookup(struct hash *pages, const void *addr);

int install_suppl_page(struct hash *pages, struct page *pg, void *upage);
bool install_page(void *upage, void *kpage, bool writable);
#endif /* vm/page.h */
