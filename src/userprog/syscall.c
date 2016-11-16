#include "userprog/syscall.h"
#include <stdio.h>
#include "threads/synch.h"
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/page.h"
#include "vm/frame.h"


#define ARG_MAX 3

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
    
    if (pagedir_get_page(thread_current()->pagedir, ptr) == NULL) 
    {
        struct page *pg = page_lookup(thread_current()->suppl_pages, pg_round_down(ptr));

            //install page HERE to prevent page fault while accessing file system..
            int pg_location = (pg == NULL ? -1 : pg->location);

            if (pg_location == -1 || pg_location == ZERO)
                thread_set_priority(PRI_DEFAULT);
            if (pg_location == SWAP || pg_location == FILE)
                thread_set_priority(PRI_MIN);

            flag = install_suppl_page(thread_current()->suppl_pages, pg, pg_round_down(ptr));

            thread_set_priority(PRI_DEFAULT);

            //if (!flag)
            //     flag = check_stack_and_install(ptr);
            //printf("syscall %x install complete\n", ptr);

    }
    else if (pagedir_get_page(thread_current()->pagedir, ptr) != NULL)
    {   //user virtual address which is not null, and in page table
        //Here it can be in a code segment
        flag = true;        
    } 
    else {
        flag = false;
    }
    return flag;
}

bool
userptr_valid_no_code(char* ptr) {
    bool flag;
    if (!ptr || !is_user_vaddr(ptr)) 
        return false;
    
    if (pagedir_get_page(thread_current()->pagedir, ptr) == NULL) 
    {
        struct page *pg = page_lookup(thread_current()->suppl_pages, pg_round_down(ptr));

        //install page HERE to prevent page fault while accessing file system..
        int pg_location = (pg == NULL ? -1 : pg->location);

        if (pg_location == -1 || pg_location == ZERO)
            thread_set_priority(PRI_DEFAULT);
        if (pg_location == SWAP || pg_location == FILE)
            thread_set_priority(PRI_MIN);

        flag = install_suppl_page(thread_current()->suppl_pages, pg, pg_round_down(ptr));

        thread_set_priority(PRI_DEFAULT);

    }
    else if (pagedir_get_page(thread_current()->pagedir, ptr) != NULL)
    {   //user virtual address which is not null, and in page table
        //Check whether it's a code segment
        struct page *pg = page_lookup(thread_current()->suppl_pages, pg_round_down(ptr));
        if (pg != NULL) {
            if (pg->writable == false) {
                //printf("cannot write to this buffer\n");
                flag = false;
            }
            else
                flag = true;
        }
        else {
            flag = true;
        }
    } 
    else {
        flag = false;
    }
    return flag;
}


bool
userbuf_valid(char* ptr, int bufsize) {
    int flag = 1;
    int i;
    for(i=0; i<bufsize; i++) {
        if (!userptr_valid(ptr+i)) {
            flag = 0;
            break;
        }
    }
    return flag;
}

bool
userbuf_valid_no_code(char* ptr, int bufsize) {
    int flag = 1;
    int i;
    for(i=0; i<bufsize; i++) {
        if (!userptr_valid_no_code(ptr+i)) {
            flag = 0;
            break;
        }
    }
    return flag;
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
  }
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
    lock_acquire(&filesys_lock);
    int ret = filesys_create(name, size);
    lock_release(&filesys_lock);
    return ret;
}

int remove(const char *file) {
    if (!userptr_valid(file))
        exit(-1);
    lock_acquire(&filesys_lock);
    int ret = filesys_remove(file);
    lock_release(&filesys_lock);
    return ret;
}


int open(const char *name) {
    if (!userbuf_valid(name, strlen(name)+1)) {
        //printf("string ptr %x is not valid\n", name);
        exit(-1);
    }
   int fd;
   lock_acquire(&filesys_lock);
   struct file* openfile = filesys_open((const char*)name);
   lock_release(&filesys_lock);
   if (!openfile) {
       return -1;
   }

   struct list *file_list = &thread_current()->file_list;
   struct file_elem *fe = malloc(sizeof(struct file_elem));

   if (!fe) {
       lock_acquire(&filesys_lock);
       file_close(openfile);
       lock_release(&filesys_lock);
       return -1;
   }
   
   fe->name = openfile;
   fd = fe->fd = thread_current()->fd_num++;
   strlcpy(fe->filename, name, strlen(name)+1);
   list_push_back(file_list, &fe->elem);

   return fd;
}

struct file *find_file_desc(int fd) {
    struct list_elem *e;
    struct file_elem *fe;
    struct file *target;
    for (e = list_begin(&thread_current()->file_list); e != list_end(&thread_current()->file_list); e = list_next(e)) {
        fe = list_entry(e, struct file_elem, elem);
        if (fe->fd == fd) {
            return fe->name;
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
            struct file *file_to_close = find_file_desc(fd);

            lock_acquire(&filesys_lock);
            file_close(file_to_close);
            lock_release(&filesys_lock);
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
	thread_current()->proc_status = status;
	thread_exit();
    

}

int exec(const char *cmd_line) {
    if (!userbuf_valid(cmd_line, strlen(cmd_line)+1)) 
        exit(-1);
	int pid = process_execute(cmd_line);
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

    //printf("user buffer check finish\n");
    const char *buf = (const char*)buffer;
    if (fd == STDOUT_FILENO) {
        putbuf((const char*) buf, size);
        return size;
    }

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
        lock_acquire(&filesys_lock);
        int ret = file_write(file_to_write, (const void*)buffer, size);
        lock_release(&filesys_lock);
		return ret;
    }
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

    char *buf = (char *)buffer;
    if (fd == STDIN_FILENO) {
        int index = 0;
        for (index = 0 ; index < size ; index++) {
            buf[index] = input_getc();
        }
        return index;
    }

    //read from file
    //printf("System call read\n");

    struct file *file_to_read = find_file_desc(fd);
    //printf("found file desc\n");
    if(file_to_read) {
    	lock_acquire(&filesys_lock);
        int ret =  file_read(file_to_read, (void *)buffer, (int)size);
        lock_release(&filesys_lock);
		return ret;
    }
    //printf("read end\n");
    return -1;
}

int filesize(int fd) {

    struct file *target = find_file_desc(fd);

	lock_acquire(&filesys_lock);
    int ret = file_length(target);
    lock_release(&filesys_lock);
	return ret;
}

void seek(int fd, unsigned position) {

    struct file *file_to_seek = find_file_desc(fd);
    if(!file_to_seek) {
		exit(-1);
	}

	lock_acquire(&filesys_lock);
    file_seek(file_to_seek, position);
	lock_release(&filesys_lock);
}

int tell(int fd) {

    struct file *file_to_tell = find_file_desc(fd);

    if(!file_to_tell) {
        exit(-1);
    }

    lock_release(&filesys_lock);
    int ret = file_tell(file_to_tell);
    lock_release(&filesys_lock);
    return ret;
}

