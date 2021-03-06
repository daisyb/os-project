#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "lib/stdbool.h"
#include "process.h"
#include <list.h>

#define CLOSE_ALL -1
#define ERROR -1

void syscall_init (void);
int sys_write (int, void *, unsigned);
int sys_create (const char *, unsigned);
int sys_open (const char *);
void sys_exit (int status);
void sys_halt (void) NO_RETURN;
pid_t sys_exec (const char *);
int sys_wait (pid_t);
int get_handle (void);
void sys_close (int handle);
int sys_remove (const char *);
int sys_filesize (int handle);
int sys_read (int handle, uint8_t *buffer, unsigned size, void *esp);
unsigned sys_tell (int handle);
void sys_seek (int handle, unsigned position);
int sys_mmap (int handle, void *vaddr);
void sys_munmap (int mapping);

/* Stack */
bool is_stack_access(void *vaddr, void *esp);
bool try_grow_stack(void *uaddr, void *esp);
#endif /* userprog/syscall.h */
