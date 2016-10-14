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

struct process {
    int exit;
	tid_t pid;
    int status;
    struct list_elem elem;
    int fd_num;
	int load;
	bool waited;
    struct list file_list;
};

/*struct child_elem {
	struct list_elem elem;
	int exit;
	int status;
	int pid;
	int load;
	bool waited;
}*/

void syscall_init (void);

#endif /* userprog/syscall.h */
