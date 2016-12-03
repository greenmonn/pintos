#include "userprog/syscall.h"
#include <stdio.h>
#include "threads/synch.h"
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "threads/pte.h"
#include "filesys/directory.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"

#define ARG_MAX 3
#define STACK_SIZE 262144

static void syscall_handler (struct intr_frame *);

struct lock filesys_lock;

void 
filesys_lock_acquire (void)
{
    lock_acquire(&filesys_lock);
}

void
filesys_lock_release (void)
{
    lock_release(&filesys_lock);
}
void
syscall_init (void) 
{ 
  //file_counter = 0;
  lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}
bool
userptr_valid(char* ptr) {
    bool flag;
	if (!ptr || !is_user_vaddr(ptr)) 
		return false;

	if (pagedir_get_page(thread_current()->pagedir, ptr)) {
		return true;
	}

	struct page *pg = page_lookup(thread_current()->suppl_pages, pg_round_down(ptr));

	/*if (pg != NULL && pg->location == 0) {
		return true;
	}*/


	flag = install_suppl_page(thread_current()->suppl_pages, pg, ptr);

    return flag;
}

bool
userptr_valid_no_code(char* ptr) {
	bool flag;
    if (!ptr || !is_user_vaddr(ptr)) 
		return false;
	
	uint32_t* pte;
	if (pagedir_get_page(thread_current()->pagedir,ptr))
 	{
		pte = lookup_page(thread_current()->pagedir, ptr, false);
		if((*pte & PTE_W) != 0) {
			return true;
		} 
	}

	
	struct page *pg = page_lookup(thread_current()->suppl_pages, pg_round_down(ptr));

	flag = install_suppl_page(thread_current()->suppl_pages, pg, ptr);

    return flag;
}


bool
userbuf_valid(char* ptr, int bufsize) {
    if (ptr >= PHYS_BASE)
        exit(-1);
    void* pg = pg_round_down(ptr);
    int32_t i;
    for(i=pg; i<ptr+bufsize; i+=PGSIZE) {
        if (!userptr_valid(i)) {
            return false;

        }
        struct page *pg = page_lookup(thread_current()->suppl_pages, (void*)i);
        pg->fr->pin = true;
    }
    return true;
}

bool
userbuf_valid_no_code(char* ptr, int bufsize) {
    if (ptr >= PHYS_BASE)
        exit(-1);
    void* pg = pg_round_down(ptr);
    int32_t i;
    for(i=pg; i<ptr+bufsize; i+=PGSIZE) {
        if (!userptr_valid_no_code(i)) {
            return false;
        }
struct page *pg = page_lookup(thread_current()->suppl_pages, (void*)i);
        pg->fr->pin = true;
    }
    
    return true;
}
    
        
 
void get_arg(struct intr_frame *f, char** arg, int n) {
    char* curptr = f->esp + sizeof(int);
    int i;
    for (i=0; i<n; i++) {
        if (!userptr_valid(curptr)) {
			exit(-1);
        }
        arg[i] = *(char**)(curptr);
        curptr += sizeof(char*);
    }
}

void frame_pin(void *buffer, unsigned size) {
    int32_t i;
    for (i = pg_round_down(buffer); i < buffer+size; i+=PGSIZE) {
        struct page *pg = page_lookup(thread_current()->suppl_pages, (void*)i);
        pg->fr->pin = true;
    }
}
void frame_unpin(void *buffer, unsigned size) {
    int32_t i;
    for (i = pg_round_down(buffer); i < buffer+size ; i+=PGSIZE) {
        struct page *pg = page_lookup(thread_current()->suppl_pages, (void*)i);
        pg->fr->pin = false;
    }
}

void ptr_pin(void* vaddr) {
	struct page *pg = page_lookup(thread_current()->suppl_pages, vaddr);
	
	if (pg) pg->fr->pin = true;
}

void ptr_unpin(void* vaddr) {
	struct page *pg = page_lookup(thread_current()->suppl_pages, vaddr);

	if (pg) pg->fr->pin = false;
}



  
static void
syscall_handler (struct intr_frame *f) 
{
  char* arg[ARG_MAX];
  int retval;

  //printf("system call!\n");
  thread_current()->esp = f->esp;

  if (!userptr_valid(f->esp)) {
      exit(-1);
  }

  ptr_pin(pg_round_down((void*)f->esp));

  switch (*(int*)(f->esp)) 
  {
    case SYS_HALT: 
	{
        power_off();
	    break;  
	}
    case SYS_EXIT:
	{
        get_arg(f,arg, 1);
	    exit((int)arg[0]);
        break;
	}
	case SYS_EXEC:
	{
		get_arg(f, arg, 1); 
		if (!userptr_valid(arg[0])) {
            exit(-1);
        }
        f->eax = exec((const char* )arg[0]);
        break;
	}
    case SYS_WAIT:
	{
		get_arg(f, arg, 1);
        f->eax = wait((int)arg[0]);
        break;
	}
	case SYS_CREATE:
	{
        get_arg(f, arg, 2);
        f->eax = create((const char*)arg[0], (unsigned)arg[1]);
        break;
	}
	case SYS_REMOVE:
	{
        get_arg(f, arg, 1);
        f->eax = remove((const char*)arg[0]);
        break;
	}
	case SYS_OPEN:
	{	
		get_arg(f, arg, 1);
        f->eax = open((const char*)arg[0]);
        break;
	}
	case SYS_FILESIZE:
	{
	    get_arg(f, arg, 1);
        f->eax = filesize((int)arg[0]);
        break;
	}
	case SYS_READ:
	{	
	    get_arg(f, arg, 3);
        //printf("read system call\n");
		f->eax = read((int)arg[0], (void*)arg[1], (unsigned)arg[2]);
        //printf("finish\n");
        break;
	}
	case SYS_WRITE:
	{
		get_arg(f, arg, 3);
        //printf("write system call\n");
		f->eax = write((int)arg[0],(const void*) arg[1],(unsigned) arg[2]);
        //printf("finish\n");
        break;
	}
	case SYS_SEEK:
	{
        get_arg(f, arg, 2);
        //printf("seek system call\n");
        seek((int)arg[0], (unsigned)arg[1]);
        //printf("finish\n");
        break;
	}
	case SYS_TELL:
	{
        get_arg(f, arg, 1);
        f->eax = tell((int)arg[0]);
        break;
	}
	case SYS_CLOSE:
	{
		get_arg(f, arg, 1);
		close(arg[0]);
        break;
	}
	case SYS_MMAP:
	{
		get_arg(f, arg, 2);
		f->eax = mmap(arg[0], (void*)arg[1]);
		break;
	}
	case SYS_MUNMAP:
	{
		get_arg(f, arg, 1);
		munmap(arg[0]);
		break;
	}
	case SYS_CHDIR:
	{
		get_arg(f, arg, 1);
		f->eax = chdir((const char*)arg[0]);
		break;
	}
	case SYS_MKDIR:
	{
		get_arg(f, arg, 1);
		f->eax = mkdir((const char*)arg[0]);
		break;
	}
	case SYS_READDIR:
	{
		get_arg(f, arg, 2);
		f->eax = readdir((int) arg[0], (char *)arg[1]);
		break;
	}
	case SYS_ISDIR:
	{
		get_arg(f, arg, 1);
		f->eax = isdir((int) arg[0]);
		break;
	}
	case SYS_INUMBER:
	{
		get_arg(f, arg, 1);
		f->eax = inumber((int) arg[0]);
		break;
	}
  }
  ptr_unpin(pg_round_down((void*)f->esp));
}

/* CREATE : limitations 
 * No internal synchronization (only one process at a time is executing file system code
 * File size if fixed at creation time
 * File data is allocated as a single extent
 * no subdirectories(only root?)
 * file name limit 14 characters
 * no file system repair tool
 */
int create(const char *name, unsigned size) {
    if (!userbuf_valid(name, strlen(name)+1))
        exit(-1);
    if (strlen(name) > 14) {
        return 0;
    }
    //frame_pin((void*)name, strlen(name)+1);
	lock_acquire(&filesys_lock);
    int ret = filesys_create(name, size);
    lock_release(&filesys_lock);
	frame_unpin((void*)name, strlen(name)+1);
    return ret;
}

int remove(const char *file) {
    if (!userptr_valid(file))
        exit(-1);

	struct dir *temp_dir;

	if (file[0] == '/') {
		temp_dir = dir_open_root();
	} else {
		temp_dir = thread_current()->current_dir;	
	}
	
	int count = 0;
	char *save_ptr_1, *token_1;
	for (token_1 = strtok_r(file, "/", &save_ptr_1); token_1 != NULL;
			token_1 = strtok_r(NULL, " ", &save_ptr_1)) {
		count++;
	}

	int i = 0;
	char *save_ptr_2, *token_2 , *name;
	for (token_2 = strtok_r(file, "/", &save_ptr_2); token_2 != NULL; 
				token_2 = strtok_r (NULL, "/", &save_ptr_2)) {
		struct inode *temp_inode;
		if (i<count-1) {
			dir_lookup(temp_dir, token_2, &temp_inode);
			if (!temp_inode) {
				return -1;
			}
			dir_close(temp_dir);
			temp_dir = dir_open(temp_inode);
			i++;
		} else {
			name = token_2;
		}
	}

	struct inode *temp_inode;
	dir_lookup(temp_dir, name, &temp_inode);
	if (!temp_inode) {
		return -1;
	}

	struct dir_entry e;
	int pos = 2*(sizeof e);
	while (inode_read_at(temp_inode, &e, sizeof e, pos) == sizeof e) {
		pos += sizeof e;
		if (e.in_use)
		{
			return -1;
		}
	}

	int ret;
	//frame_pin((void*)file, strlen(file)+1);
	if (!temp_inode->data.is_dir) {
    	lock_acquire(&filesys_lock);
    	ret = filesys_remove(name);
    	lock_release(&filesys_lock);
	} else {
		ret = dir_remove(temp_dir, name);
		dir_close(temp_dir);
	}
	frame_unpin((void*)file, strlen(file)+1);
    return ret;
}


int open(const char *name) {
	if (!userbuf_valid(name, strlen(name)+1)) {
        //printf("string ptr %x is not valid\n", name);
        exit(-1);
    }
	struct dir *temp_dir;
	if (name[0] == '/') {
		temp_dir = dir_open_root();
	} else {
		temp_dir = thread_current()->current_dir;	
		printf("%x\n", temp_dir);
	}
	
	int count = 0;
	char *save_ptr_1, *token_1;
	for (token_1 = strtok_r(name, "/", &save_ptr_1); token_1 != NULL;
			token_1 = strtok_r(NULL, " ", &save_ptr_1)) {
		count++;
	}

	printf("count : %d\n",count);

	int i = 0;
	char *save_ptr_2, *token_2;
	char name_2[14];
	for (token_2 = strtok_r(name, "/", &save_ptr_2); token_2 != NULL; 
				token_2 = strtok_r (NULL, "/", &save_ptr_2)) {
		struct inode *temp_inode;
		if (i<count-1) {
			dir_lookup(temp_dir, token_2, &temp_inode);
			if (!temp_inode) {
				return -1;
			}
			dir_close(temp_dir);
			temp_dir = dir_open(temp_inode);
			printf("token : %s\n", token_2);
			i++;
		} else {
			strlcpy(name_2,token_2,strlen(token_2)+1);
		}
	printf("token : %s\n", token_2);
	}
	printf("token : %s\n", token_2);
	if (count == 1) {
		printf("strlcpy before\n");
		strlcpy(name_2, name, strlen(name)+1);
		printf("strlcpy after\n");
	}
	printf("name_2 : %s\n", name_2);
	struct inode *temp_inode;
	dir_lookup(temp_dir, name_2, &temp_inode);
	if (!temp_inode) {
printf("1\n");
		return false;
	}
	

	int fd;
	if (!temp_inode->data.is_dir) {
		//frame_pin((void*)name, strlen(name)+1);
		lock_acquire(&filesys_lock);
		struct file* openfile = filesys_open_dir((const char*)name_2, temp_dir);
		lock_release(&filesys_lock);
		if (!openfile) {
			frame_unpin((void*)name, strlen(name)+1);
			return -1;
		}

		struct list *file_list = &thread_current()->file_list;
		struct file_elem *fe = malloc(sizeof(struct file_elem));

		if (!fe) {
			lock_acquire(&filesys_lock);
			file_close(openfile);
			lock_release(&filesys_lock);
			frame_unpin((void*)name, strlen(name)+1);
			return -1;
		}
		fe->dir_name = NULL;
		fe->name = openfile;
		fd = fe->fd = thread_current()->fd_num++;
		strlcpy(fe->filename, name_2, strlen(name_2)+1);
		list_push_back(file_list, &fe->elem);
		frame_unpin((void*)name, strlen(name)+1);
		return fd;
	} else {
		dir_close(temp_dir);
		temp_dir = dir_open(temp_inode);
		if (!temp_dir) {
			frame_unpin((void*)name, strlen(name)+1);
			return -1;
		}

		struct list *file_list = &thread_current()->file_list;
		struct file_elem *fe = malloc(sizeof(struct file_elem));

		if (!fe) {
			dir_close(temp_dir);
			frame_unpin((void*)name, strlen(name)+1);
			return -1;
		}
		
		fe->dir_name = temp_dir;
		fe->name = NULL;
		fd = fe->fd = thread_current()->fd_num++;
		//strlcpy(fe->filename, name_2, strlen(name_2)+1);
		list_push_back(file_list, &fe->elem);
		frame_unpin((void*)name, strlen(name)+1);
		return fd;

	}
	
}

struct file *find_file_desc(int fd) {
    struct list_elem *e;
    struct file_elem *fe;
    for (e = list_begin(&thread_current()->file_list); e != list_end(&thread_current()->file_list); e = list_next(e)) {
        fe = list_entry(e, struct file_elem, elem);
        if (fe->fd == fd) {
            return fe->name;
        }
    }
    return NULL;
}

struct dir *find_dir_desc(int fd) {
    struct list_elem *e;
    struct file_elem *fe;
    for (e = list_begin(&thread_current()->file_list); e != list_end(&thread_current()->file_list); e = list_next(e)) {
        fe = list_entry(e, struct file_elem, elem);
        if (fe->fd == fd) {
            return fe->dir_name;
        }
    }
    return NULL;
}

void close(int fd) {

    struct list *file_list = &thread_current()->file_list;
    struct list_elem *e;
    struct file_elem *fe;
    

    for (e = list_begin(file_list); e != list_end(file_list); e = list_next(e)) {
        fe = list_entry(e, struct file_elem, elem);
        if (fe->fd == fd) {
			if (!fe->dir_name) {
            	struct file *file_to_close = find_file_desc(fd);

            	lock_acquire(&filesys_lock);
            	file_close(file_to_close);
            	lock_release(&filesys_lock);
			} else {
				struct dir *dir_to_close = find_dir_desc(fd);
				dir_close(dir_to_close);
			}
            e = list_next(e);
            list_remove(list_prev(e));
            free(fe);
            e = list_prev(e);
			break;
        }
    }

}

void exit(int status) {
    struct child_elem *child = find_child(thread_current()->tid);
    if (child != NULL) {
        child->status = status;
        child->exit = 1;

    }
    //printf("called exit on thread %x : %s\n", thread_current(), thread_current()->name);
	printf("%s: exit(%d)\n", thread_current()->name, status);
	thread_current()->proc_status = status;
	thread_exit();
    

}

int exec(const char *cmd_line) {
    if (!userbuf_valid(cmd_line, strlen(cmd_line)+1)) 
        exit(-1);
	//frame_pin((void*)cmd_line, strlen(cmd_line)+1);
	int pid = process_execute(cmd_line);
	frame_unpin((void*)cmd_line, strlen(cmd_line)+1);
	return pid;
}

int wait(int pid) {
    int status;
	status = process_wait(pid);
    return status;
}
    
char *find_file_name(int fd) {
    struct list_elem *e;
    struct file_elem *fe;
    struct file *target;
    for (e = list_begin(&thread_current()->file_list); e != list_end(&thread_current()->file_list); e = list_next(e)) {
        fe = list_entry(e, struct file_elem, elem);
        if (fe->fd == fd) {
            return fe->filename;
        }
    }
    return NULL;
}

int write(int fd, const void *buffer, unsigned size)
{
    if (!userbuf_valid(buffer, size)) {
        exit(-1);
    }
	//frame_pin(buffer, size);

    //printf("user buffer check finish\n");
    const char *buf = (const char*)buffer;
    if (fd == STDOUT_FILENO) {
        putbuf((const char*) buf, size);
		frame_unpin(buffer,size);
        return size;
    }
    
	lock_acquire(&filesys_lock);
    //write to file
    struct file *file_to_write = find_file_desc(fd);
    //char* filename = find_file_name(fd);
	
/*
    //Cannot write executing code (for rox tests)
    if (filename != NULL && !strcmp(filename, thread_current()->name)) {
		return 0;
    }
    */

    if (file_to_write) {
        //lock_acquire(&filesys_lock);
        int ret = file_write(file_to_write, (const void*)buffer, size);
        lock_release(&filesys_lock);
		frame_unpin(buffer, size);
		return ret;
    }
	lock_release(&filesys_lock);
    frame_unpin(buffer, size);
    return 0;

}

int read(int fd, void *buffer, unsigned size)
{
    if(!userbuf_valid_no_code(buffer, size)) {
        exit(-1);
    }
    //TODO : deny buffer pointing code segment..
    //printf("user buffer check finish\n");
    //char* kerbuf = pagedir_get_page(thread_current()->pagedir, buffer);
	//frame_pin(buffer, size);
    char *buf = (char *)buffer;
    if (fd == STDIN_FILENO) {
        int index = 0;
        for (index = 0 ; index < size ; index++) {
            buf[index] = input_getc();
        }
		frame_unpin(buffer, size);
        return index;
    }

    //read from file
    
	lock_acquire(&filesys_lock);
	struct file *file_to_read = find_file_desc(fd);
    //printf("found file desc\n");
    if(file_to_read) {
    	//lock_acquire(&filesys_lock);
        int ret =  file_read(file_to_read, (void *)buffer, (int)size);
		frame_unpin(buffer, size);
        lock_release(&filesys_lock);
		return ret;
    }
	lock_release(&filesys_lock);
    frame_unpin(buffer, size);
    return -1;
}

int filesize(int fd) {
	lock_acquire(&filesys_lock);
    struct file *target = find_file_desc(fd);

	//lock_acquire(&filesys_lock);
    int ret = file_length(target);
    lock_release(&filesys_lock);
	return ret;
}

void seek(int fd, unsigned position) {
	lock_acquire(&filesys_lock);
    struct file *file_to_seek = find_file_desc(fd);
    if(!file_to_seek) {
		lock_release(&filesys_lock);
		exit(-1);
	}

	//lock_acquire(&filesys_lock);
    file_seek(file_to_seek, position);
	lock_release(&filesys_lock);
}

int tell(int fd) {
	//printf("wow\n");
	lock_acquire(&filesys_lock);
    struct file *file_to_tell = find_file_desc(fd);

    if(!file_to_tell) {
		lock_release(&filesys_lock);
        exit(-1);
    }

    //lock_acquire(&filesys_lock);
    int ret = file_tell(file_to_tell);
    lock_release(&filesys_lock);
    return ret;
}

int mmap (int fd, void *addr) {
	//printf("fd: %d\n",fd);
	//printf("addr: %x\n", addr);
	if (fd == 0 || fd == 1)
		return -1;

	if (addr == NULL || addr == 0x0 || pg_ofs(addr) != 0 || !is_user_vaddr(addr))
        return -1;

	lock_acquire(&filesys_lock);

	struct file *file_to_mmap = find_file_desc(fd);
	if (!file_to_mmap) {
		lock_release(&filesys_lock);
		return -1;
	}

	file_to_mmap = file_reopen(file_to_mmap);

	uint32_t read_bytes = file_length(file_to_mmap);
	if ( file_length(file_to_mmap) <= 0) {
		lock_release(&filesys_lock);
		return -1;
	}

	lock_release(&filesys_lock);

	int32_t ofs = 0;
	thread_current()->mapid++;
    uint32_t first_addr = addr;

	int pg_count = 0;
	while (read_bytes > 0)
	{
		uint32_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        //printf("mmap addr : %x\n", addr);
		uint32_t page_zero_bytes = PGSIZE - page_read_bytes;
		if (page_lookup(thread_current()->suppl_pages, addr)) {
			//munmap(thread_current()->mapid);
            while(addr>first_addr) {
                addr -=PGSIZE;
                struct page *pg = page_lookup(thread_current()->suppl_pages, addr);
                hash_delete(thread_current()->suppl_pages, &pg->elem);
				free(pg);
            }
			//printf("1\n");
			return -1;

		}
		struct page *mmap_pg = make_page(addr , MMAP);
		
		page_set_file (thread_current()->suppl_pages, mmap_pg, file_to_mmap, ofs ,true, page_read_bytes);
		

		read_bytes -= page_read_bytes;
		ofs += page_read_bytes;
		addr += PGSIZE;
		pg_count++;
	}
	struct mmap_elem *m = malloc(sizeof(struct mmap_elem));
	m->addr = first_addr;
	m->pg_count = pg_count;
	m->mapid = thread_current()->mapid;
	list_push_back(&thread_current()->mmap_list, &m->elem);

	

	return thread_current()->mapid;
}

void munmap (int mapid) {
	struct list_elem *e;
	struct mmap_elem *me;
	if (!list_empty(&thread_current()->mmap_list)){
		for (e = list_begin(&thread_current()->mmap_list); e != list_end(&thread_current()->mmap_list); e = list_next(e)) {
			me = list_entry(e, struct mmap_elem, elem);
			if (me->mapid == mapid) {
				break;
			}
		}
		list_remove(e);
	} else {
		return;
	}
	void* addr = me->addr;
    struct file* unmap_file;

	struct page *mmap_pg;

	
	uint32_t ofs = 0;

	lock_acquire(&filesys_lock);
	int i;
	for (i = 0; i<me->pg_count; i++)
    {

        mmap_pg = page_lookup(thread_current()->suppl_pages,addr);


        if (pagedir_is_dirty(thread_current()->pagedir,addr)) {

            mmap_pg->fr->pin = true;

            file_write_at(mmap_pg->file, addr, mmap_pg->page_read_bytes, ofs);

        }

        if (pagedir_get_page(thread_current()->pagedir,addr)) {
            frame_free(mmap_pg->fr);

            pagedir_clear_page(thread_current()->pagedir,addr);
        }

        hash_delete(thread_current()->suppl_pages, &mmap_pg->elem);
        unmap_file = mmap_pg->file;
        free(mmap_pg);

        ofs += PGSIZE;
        addr += PGSIZE;
    }
    file_close(unmap_file);
    lock_release(&filesys_lock);
	free(me);

}

int chdir(const char *dir) {
	struct dir *temp_dir;
	
	if (dir[0] == '/') {
		temp_dir = dir_open_root();
	} else if ((dir[0] =='.' && dir[1] == '/') || (dir[0] == '.' && dir[1] == '.' && dir[2] == '/')) {
		temp_dir = thread_current()->current_dir;	
	} else {
		return false;
	}

	char *save_ptr, *token;
	for (token = strtok_r(dir, "/", &save_ptr); token != NULL; 
				token = strtok_r (NULL, "/", &save_ptr)) {
			struct inode *temp_inode;
			dir_lookup(temp_dir, token, &temp_inode);
			if (!temp_inode) {
				return false;
			}
			dir_close(temp_dir);
			temp_dir = dir_open(temp_inode);
		}
	thread_current()->current_dir = temp_dir;

	return true;
}

int mkdir (const char *dir) {
	struct dir *temp_dir;

	if (dir[0] == '/') {
		temp_dir = dir_open_root();
	} else if ((dir[0] =='.' && dir[1] == '/') || (dir[0] == '.' && dir[1] == '.' && dir[2] == '/')) {
		temp_dir = thread_current()->current_dir;	
	} else {
		return false;
	}
	
	int count = 0;
	char *save_ptr_1, *token_1;
	for (token_1 = strtok_r(dir, "/", &save_ptr_1); token_1 != NULL;
			token_1 = strtok_r(NULL, " ", &save_ptr_1)) {
		count++;
	}

	int i = 0;
	char *save_ptr_2, *token_2 , *name;
	for (token_2 = strtok_r(dir, "/", &save_ptr_2); token_2 != NULL; 
				token_2 = strtok_r (NULL, "/", &save_ptr_2)) {
		struct inode *temp_inode;
		if (i<count-1) {
			dir_lookup(temp_dir, token_2, &temp_inode);
			if (!temp_inode) {
				return false;
			}
			dir_close(temp_dir);
			temp_dir = dir_open(temp_inode);
			i++;
		} else {
			name = token_2;
		}
	}

	disk_sector_t temp_inode_s = 0;
	free_map_allocate(1,&temp_inode_s);
	dir_create(temp_inode_s, 16);
	dir_add(temp_dir, name, temp_inode_s);

	return true;

}

int readdir (int fd, char *name) {
	struct dir *dir_to_read = find_dir_desc(fd);
	return dir_readdir (dir_to_read, name);
}

int isdir(int fd) {
	struct dir *dir= find_dir_desc(fd);
	return dir->inode->is_dir;
}

int inumber (int fd) {
	struct dir *dir = find_dir_desc(fd);
	return dir->inode->sector;
}
