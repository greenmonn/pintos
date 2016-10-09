#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"

struct process {
    int exit;
    int pid;
    int status;
    struct list_elem elem;
};

void syscall_init (void);

#endif /* userprog/syscall.h */
