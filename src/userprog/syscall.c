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
	  
        break;
	}
	case SYS_REMOVE:
	{
	  
        break;
	}
	case SYS_OPEN:
	{
	  
        break;
	}
	case SYS_FILESIZE:
	{
	  
        break;
	}
	case SYS_READ:
	{
	  
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

void exit(int status) {
    thread_current()->proc->exit = 1;
	thread_current()->proc->status = status;
	printf("%s: exit(%d)\n", thread_current()->name,status);
	thread_exit(); 
}

int exec(const char *cmd_line) {
	int pid = process_execute(cmd_line);
	return pid;
}

int wait(int pid) {
    int status;
	status = process_wait(pid);
    return status;
}
    
int write(int fd, const void *buffer, unsigned size)
{
    if (fd == STDOUT_FILENO) {
        if (!userbuf_valid(buffer, size)) {
            exit(-1);
        }
        char* kerbuf = pagedir_get_page(thread_current()->pagedir, buffer);
        putbuf((const char*) kerbuf, size);
        return size;
    }
    
}
