#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"

struct file_elem {
    struct file *name;
    int fd;
    char filename[15];
    struct list_elem elem;
};

struct process {
    int exit;
    tid_t pid;
    int status;
    struct list_elem elem;
	int load;
    bool waited;
    int fd_num;
    struct list file_list;
};

void syscall_init (void);

#endif /* userprog/syscall.h */
