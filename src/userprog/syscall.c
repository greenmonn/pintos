#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

#define ARG_MAX 3

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

bool
userptr_valid(char* ptr) {
    int flag = 1;
    if (!ptr || !is_user_vaddr(ptr) || !pagedir_get_page(thread_current()->pagedir, ptr))
        flag = 0;

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

  if (!userptr_valid(f->esp)) {
      exit(-1);
  }

  switch (*(int*)(f->esp)) 
  {
    case SYS_HALT: 
	{
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
        f->eax = read((int)arg[0], (void*)arg[1], (unsigned)arg[2]);
        break;
	}
	case SYS_WRITE:
	{
	    get_arg(f, arg, 3);
        f->eax = write((int)arg[0],(const void*) arg[1],(unsigned) arg[2]);
        break;
	}
	case SYS_SEEK:
	{
	  
        break;
	}
	case SYS_TELL:
	{
	  
        break;
	}
	case SYS_CLOSE:
	{
	  
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
    if (!userptr_valid(name))
        exit(-1);
    if (strlen(name) > 14) {
        return 0;
    }
    return filesys_create(name, size);
}

int open(const char *name) {
    if (!userptr_valid(name))
        exit(-1);
   char* kername = pagedir_get_page(thread_current()->pagedir, name);
   int fd;
   //printf("%s\n", name);
   struct file* openfile = filesys_open((const char*)kername);
   //printf("%x\n", openfile);
   if (!openfile) {
       return -1;
   }
   struct list *file_list = &thread_current()->proc->file_list;
   struct file_elem *fe = malloc(sizeof(struct file_elem));
   fe->name = openfile;
   fd = fe->fd = thread_current()->proc->fd_num++;
   list_push_back(file_list, &fe->elem);
   return fd;
}
void exit(int status) {
    thread_current()->proc->exit = 1;
	thread_current()->proc->status = status;
//	printf("%s: exit(%d)\n", thread_current()->name,status);
	thread_exit(); 
}

int exec(const char *cmd_line) {
	char *kerbuf = pagedir_get_page(thread_current()->pagedir, cmd_line);
    int pid = process_execute(kerbuf);
	return pid;
}

int wait(int pid) {
    int status;
	status = process_wait(pid);
    return status;
}
    
struct file *find_file_desc(int fd) {
    struct list_elem *e;
    struct file_elem *fe;
    struct file *target;
    for (e = list_begin(&thread_current()->proc->file_list); e != list_end(&thread_current()->proc->file_list); e = list_next(e)) {
        fe = list_entry(e, struct file_elem, elem);
        if (fe->fd == fd) {
            return fe->name;
        }
    }
    return NULL;
}


int write(int fd, const void *buffer, unsigned size)
{
    if (!userbuf_valid(buffer, size)) {
        exit(-1);
    }
    char* kerbuf = pagedir_get_page(thread_current()->pagedir, buffer);

    if (fd == STDOUT_FILENO) {
        putbuf((const char*) kerbuf, size);
        return size;
    }

    //write to file
    struct file *file_to_write = find_file_desc(fd);
   
    if (file_to_write) {
        return file_write(file_to_write, (const void*)kerbuf, size);
    }
    return 0;

}

int read(int fd, void *buffer, unsigned size)
{
    if(!userbuf_valid(buffer, size)) {
        exit(-1);
    }
    char* kerbuf = pagedir_get_page(thread_current()->pagedir, buffer);

    if (fd == STDIN_FILENO) {
        int index = 0;
        for (index = 0 ; index < size ; index++) {
            kerbuf[index] = input_getc();
        }
        return index;
    }

    //read from file
    struct file *file_to_read = find_file_desc(fd);
    
    if(file_to_read) {
        return file_read(file_to_read, (void*)kerbuf, (int)size);
        }

    return -1;
}

int filesize(int fd) {
    struct file *target = find_file_desc(fd);
    return file_length(target);
}
