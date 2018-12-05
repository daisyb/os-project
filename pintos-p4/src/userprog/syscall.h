#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "lib/stdbool.h"
#include "process.h"
#include <list.h>

/* Note for Raphael: create, remove */

/* Process identifier. */
void syscall_init (void);
int sys_write (int handle, void *usrc_, unsigned size);
int sys_create (const char *file, unsigned initial_size);
int sys_open (const char *file);
void sys_exit (int status);
void sys_halt (void) NO_RETURN;
pid_t sys_exec (const char *file);
int sys_wait (pid_t);
int get_handle (void);
void sys_close (int handle);
int sys_remove (const char *file);
int sys_filesize (int handle);
int sys_read (int handle, void *buffer, unsigned size);
unsigned tell (int handle);
void seek (int handle, unsigned position);
bool sys_chdir(const char *dir);
bool sys_mkdir(const char *dir);
bool sys_readdir (int fd, char *name);
bool sys_isdir (int fd);
int sys_inumber (int fd);

#endif /* userprog/syscall.h */
