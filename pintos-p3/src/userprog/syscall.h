#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "lib/stdbool.h"
#include "process.h"
#include <list.h>

void syscall_init (void);
int sys_write (int, void *, unsigned, void *);
int sys_create (const char *, unsigned, void *);
int sys_open (const char *, void *);
void sys_exit (int status);
void sys_halt (void) NO_RETURN;
pid_t sys_exec (const char *, void *);
int sys_wait (pid_t);
int get_handle (void);
void sys_close (int handle);
int sys_remove (const char *, void *);
int sys_filesize (int handle);
int sys_read (int handle, uint8_t *buffer, unsigned size, void *);
unsigned tell (int handle);
void seek (int handle, unsigned position);

/* Stack */
bool is_stack_access(void *vaddr, void *);
bool try_grow_stack(void *uaddr, void *);
#endif /* userprog/syscall.h */
