#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"

struct process {
    int exit;
    tid_t pid;
    int status;
    struct list_elem elem;
	int load;
    bool waited;
};

void syscall_init (void);

#endif /* userprog/syscall.h */
