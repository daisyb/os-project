#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <string.h>
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "filesys/filesys.h"
#include "filesys/directory.h"
#include "devices/shutdown.h"
#include "pagedir.h"
#include "lib/stdbool.h"
#include "devices/input.h"

static void get_args (void *f_esp, int *args, int argc);
static void is_valid_pointer (const void *p);
/* Copies a byte from user address USRC to kernel address DST. USRC must
   be below PHYS_BASE. Returns true if successful, false if a segfault occurred. */
/* PROVIDED */
static inline bool get_user (uint8_t *dst, const uint8_t *usrc){
  int eax;
  asm ("movl $1f, %%eax; movb %2, %%al; movb %%al, %0; 1:"
       : "=m" (*dst), "=&a" (eax) : "m" (*usrc));
  return eax != 0;
}

/* Writes BYTE to user address UDST. UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
/* PROVIDED */
static inline bool put_user (uint8_t *udst, uint8_t byte){
  int eax;
  asm ("movl $1f, %%eax; movb %b2, %0; 1:"
       : "=m" (*udst), "=&a" (eax) : "q" (byte));
  return eax != 0;
}

/* Copies SIZE bytes from user address USRC to kernel address DST. Calls
   thread_exit() if any of the user accesses are invalid. */
static void copy_in (void *dst_, const void *usrc_, size_t size){
  uint8_t *dst = dst_;
  const uint8_t *usrc = usrc_;
  for (; size > 0; size--, dst++, usrc++)
    if (usrc >= (uint8_t *) PHYS_BASE || !get_user (dst, usrc))
      sys_exit(-1);
}

static char *copy_in_string (const char *us){
  char *ks;
  int i;

  /* allocates a new single page ks */
  ks = palloc_get_page (0);
  if (ks == NULL)
    thread_exit ();

  for (i=0; i<PGSIZE; i++){
    if (us >= (const char *) PHYS_BASE ||
        !get_user ((uint8_t *)ks+i, (uint8_t *)us+i)){
      palloc_free_page(ks);
      sys_exit(-1);
    }      
    if (us[i] == '\0'){
      return ks;
    }
  }
  printf("exceeded page size in copy_in_string\n");
  return ks;
}


typedef int (*handler_function)(int, int, int);

struct handler_entry {
  unsigned call_nr;
  unsigned argc;
  handler_function func;
};

struct handler_entry handlers[] = {
  {SYS_WRITE, 3, (handler_function)sys_write},
  {SYS_CREATE, 2, (handler_function)sys_create},
  {SYS_EXIT, 1, (handler_function)sys_exit},
  {SYS_HALT, 0, (handler_function)sys_halt},
  {SYS_EXEC, 1, (handler_function)sys_exec},
  {SYS_WAIT, 1, (handler_function)sys_wait},
  {SYS_OPEN, 1, (handler_function)sys_open},
  {SYS_CLOSE, 1, (handler_function)sys_close},
  {SYS_REMOVE, 1, (handler_function)sys_remove},
  {SYS_FILESIZE, 1, (handler_function)sys_filesize},
  {SYS_READ, 3, (handler_function)sys_read},
  {SYS_SEEK, 2, (handler_function)seek},
  {SYS_TELL, 1, (handler_function)tell},
  {SYS_CHDIR, 1, (handler_function)sys_chdir},
  {SYS_MKDIR, 1, (handler_function)sys_mkdir},
  {SYS_READDIR, 2, (handler_function)sys_readdir},
  {SYS_ISDIR, 1, (handler_function)sys_isdir},
  {SYS_INUMBER, 1, (handler_function)sys_inumber}
  };


#define num_handlers (sizeof(handlers) / sizeof(struct handler_entry))

static void syscall_handler (struct intr_frame *f){
  unsigned call_nr;
  is_valid_pointer ((const void *) f->esp);
  copy_in (&call_nr, f->esp, sizeof call_nr);

  unsigned i;
  for (i = 0; i < num_handlers; i++){
    if (handlers[i].call_nr == call_nr){
      break;
    }
  }
  if (i == num_handlers){
    printf("Unsupported syscall: %d\n", call_nr);
    sys_exit(-1);
  }

  struct handler_entry syscall = handlers[i];

  // copy the args (depends on arg_cnt for every syscall).
  // note that if the arg passed is a pointer (e.g. a string),
  // then we just copy the pointer here, and you still need to
  // call 'copy_in_string' on the pointer to pass the string
  // from user space to kernel space
  int args[3];
  memset (args, 0, sizeof *args);

  get_args (f->esp, &args[0], syscall.argc);

  f->eax = syscall.func(args[0], args[1], args[2]);
}

static void get_args (void *f_esp, int *args, int argc){
  int i;
  int *p;
  for (i=0; i<argc; i++){
    p = (int *) f_esp + 1 + i;
    is_valid_pointer ((const void *) p);
    args[i] = *p;
  }
}

void syscall_init (void){
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}


/* Write system call */
int sys_write (int handle, void *usrc_, unsigned size){
  is_valid_pointer (usrc_);
  int bytes;    
  if (handle == STDOUT_FILENO){
    putbuf (usrc_, size);
    return size;
  }
  lock_acquire (&filesys_lock);
  struct file_descriptor *fd = lookup_fd(handle);
  if (!fd || fd->type != FILE_INODE) {
    lock_release (&filesys_lock);
    sys_exit (-1);
  }
  bytes = file_write (fd->data.file, usrc_, size);
  lock_release (&filesys_lock);
  return bytes;
}

/* Exit system call */
void sys_exit (int status){
  struct thread *cur = thread_current();
  char *format_str = "%s: exit(%d)";
  int len = strlen(cur->name) + strlen(format_str);
  char buf[len];
  snprintf(buf, len, format_str, cur->name, status);
  puts(buf);
  cur->process->exit_status = status;
  thread_exit();
}

/* Halt system call */
void sys_halt (void){
  shutdown_power_off();
}

/* Exec system call */
pid_t sys_exec (const char *file_){
  char *file = copy_in_string(file_);
  pid_t pid = process_execute(file);
  struct process *child = thread_get_child_process(pid);
  if (!child) return -1;
  sema_down(&child->sema_load);
  if (!child->loaded) return -1;
  palloc_free_page (file);
  return pid;
}

/* Wait system call */
int sys_wait (pid_t pid){
  return process_wait(pid);
}

/* Create system call */
int sys_create (const char *file, unsigned initial_size){
  is_valid_pointer (file);
  if (!file)
    return 0;
  if (strcmp(file, "") == 0)
    return 0;

  char *kfile = copy_in_string (file);
  lock_acquire (&filesys_lock);
  int create_try = filesys_create (kfile, initial_size, FILE_INODE);
  lock_release (&filesys_lock);
  palloc_free_page (kfile);
  return create_try;
}

/* Remove system call */
int sys_remove (const char *file){
  char *kfile = copy_in_string (file);
  int remove_try = filesys_remove (kfile);
  palloc_free_page (kfile);
  return remove_try;
}


int get_handle (){
  next_fd++;
  return next_fd;
}

/*
  Allocates a file_descriptor for inode i
  adds the fd to the current thread
  returns handle or -1 if fails
*/
static inline int  fd_alloc(struct inode* i){
  struct file_descriptor *new_fd = (struct file_descriptor*) malloc (sizeof(struct file_descriptor));
  new_fd->handle = get_handle ();
  new_fd->type = inode_get_type(i);
  bool success = false;
  switch(new_fd->type){
  case FILE_INODE:
    new_fd->data.file = file_open(i);
    success = new_fd->data.file;
    break;
  case DIR_INODE:
    new_fd->data.dir = dir_open(i);
    success = new_fd->data.dir;
    break;
  }
  if (!success){
    free(new_fd);
    return -1;
  }
  struct thread *cur = thread_current();
  list_push_front(&cur->process->fd_list, &new_fd->elem);
  return new_fd->handle;
}

/* Open system call */
int sys_open (const char *file){
  is_valid_pointer (file);
  char *kfile = copy_in_string (file);
  lock_acquire (&filesys_lock);
  struct inode *open_try = filesys_open (kfile);
  lock_release (&filesys_lock);
  if (!open_try){
    return -1;
  }
  int handle = fd_alloc(open_try);
  palloc_free_page (kfile);
  return handle;
}


/* Close system call */
void sys_close (int handle){
  if (handle < 2)
    sys_exit (-1); 
  lock_acquire (&filesys_lock); 
  struct file_descriptor *fd = lookup_fd (handle);
  lock_release (&filesys_lock);
  if (!fd) return;
  switch(fd->type){
  case FILE_INODE:
    file_close (fd->data.file);
    break;
  case DIR_INODE:
    dir_close(fd->data.dir);
    break;
  }
  list_remove (&fd->elem);
  free (fd);
}

/* Filesize system call */
int sys_filesize (int handle){
  lock_acquire (&filesys_lock);
  struct file_descriptor *fd = lookup_fd (handle);
  if (!fd || fd->type != FILE_INODE){
    lock_release (&filesys_lock);
    sys_exit (-1);
  }
  int bytes = file_length (fd->data.file);
  lock_release (&filesys_lock);
  return bytes;
}

/* Read system call */
int sys_read (int handle, void *buffer, unsigned size){
  is_valid_pointer (buffer);
  if (handle == STDIN_FILENO){
    unsigned i;
    uint8_t *new_buff = (uint8_t *) buffer;
    for (i=0; i<size; i++){
      new_buff[i] = input_getc ();
    }
    return size;
  }

  lock_acquire (&filesys_lock);
  struct file_descriptor *fd = lookup_fd (handle);
  if (!fd || fd->type != FILE_INODE){
    lock_release (&filesys_lock);
    sys_exit (-1);
  }
  int bytes = file_read (fd->data.file, buffer, size);
  lock_release (&filesys_lock);
  return bytes;
}

/* Tell system call */
unsigned tell (int handle){
  lock_acquire (&filesys_lock);
  struct file_descriptor *fd = lookup_fd (handle);
  if (!fd || fd->type != FILE_INODE){
    lock_release (&filesys_lock);
    sys_exit (-1);
  }
  struct file *f = fd->data.file;
  unsigned bytes = file_tell (f);
  lock_release (&filesys_lock);
  return bytes;
}

/* Seek system call */
void seek (int handle, unsigned position){
  lock_acquire (&filesys_lock);
  struct file_descriptor *fd = lookup_fd (handle);
  if (!fd || fd->type != FILE_INODE){
    lock_release (&filesys_lock);
    sys_exit (-1);
  }
  struct file *f = fd->data.file;
  file_seek (f, position);
  lock_release (&filesys_lock);
}

bool sys_chdir(const char *dir){
  lock_acquire(&filesys_lock);
  int success = filesys_chdir(dir);
  lock_release(&filesys_lock);
  return success;
}

bool sys_mkdir(const char *dir){
  lock_acquire(&filesys_lock);
  int success = filesys_create(dir, 0, DIR_INODE);
  lock_release(&filesys_lock);
  return success;
}

bool sys_readdir (int handle, char *name){
  struct file_descriptor *fd = lookup_fd (handle);
  if (fd->type != DIR_INODE) return false;
  return dir_readdir(fd->data.dir, name);
}

bool sys_isdir (int handle){
  struct file_descriptor *fd = lookup_fd (handle);
  if (!fd) return false;
  return fd->type == DIR_INODE;
}

int sys_inumber (int handle){
  struct file_descriptor *fd = lookup_fd (handle);
  if (!fd) sys_exit(-1);
  int sector = -1;
  switch(fd->type){
  case FILE_INODE:
    sector = file_get_inumber(fd->data.file);
    break;
  case DIR_INODE:
    sector = dir_get_inumber(fd->data.dir);
    break;
  }
  return sector;
}

/* Checks whether a user pointer is valid */
static void is_valid_pointer (const void *p){
  if (!p ||
      !is_user_vaddr (p) || 
      !pagedir_get_page (thread_current ()->pagedir, p)){
    sys_exit (-1);
  }
}

