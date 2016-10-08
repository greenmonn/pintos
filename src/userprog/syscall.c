#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  printf ("system call!\n");
  printf("intr_num: %x\n",f->vec_no);
  if (!pagedir_get_page(thread_current()->pagedir,(const void*)f->esp) || !(f->esp)) {
  	thread_exit();
  }

  if (!is_user_vaddr(f->esp)) {
  	thread_exit();
  }
  printf("syscall : %d\n",*(int *)(f->esp));
  switch (*(int*)(f->esp)) 
  {
    case SYS_HALT: 
	{
	  
	}
    case SYS_EXIT:
	{
	  exit(1);
	}
	case SYS_EXEC:
	{
	  
	}
    case SYS_WAIT:
	{
	  
	}
	case SYS_CREATE:
	{
	  
	}
	case SYS_REMOVE:
	{
	  
	}
	case SYS_OPEN:
	{
	  
	}
	case SYS_FILESIZE:
	{
	  
	}
	case SYS_READ:
	{
	  
	}
	case SYS_WRITE:
	{
	  
	}
	case SYS_SEEK:
	{
	  
	}
	case SYS_TELL:
	{
	  
	}
	case SYS_CLOSE:
	{
	  
	}
  }
}

void exit(int i) {
	thread_exit();
}
