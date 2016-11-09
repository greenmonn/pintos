#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"

struct file_elem {
    struct file *name;
    int fd;
    char filename[15];
    struct list_elem elem;
	struct lock *file_lock;
};

struct child_elem {
	struct list_elem elem;
	int exit;
	int status;
	tid_t pid;
	int load;
	bool waited;
    struct thread *TCB;
};

void syscall_init (void);

void filesys_lock_acquire (void);
void filesys_lock_release (void);
#endif /* userprog/syscall.h */
