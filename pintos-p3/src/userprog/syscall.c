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
#include "devices/shutdown.h"
#include "pagedir.h"
#include <stdbool.h>
#include "devices/input.h"
#include "vm/page.h"

#define PUSH_BYTES 4
#define PUSHA_BYTES 32
#define MAX_STACK_SZ 8000000 //8 MB

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

static void write_out(void *udst_, void *ksrc_, size_t size, void *esp){
  uint8_t *udst = udst_;
  uint8_t *ksrc = ksrc_;
  for (; size > 0; size--, udst++, ksrc++){
    while(udst >= (uint8_t *) PHYS_BASE || !put_user (udst, *ksrc)){
      if (!try_grow_stack(udst, esp)) sys_exit(-1);
    }
  }
}

static void write_stdin(void *udst_, size_t size, void *esp){
  uint8_t *udst = udst_;
  for (; size > 0; size--, udst++){
    while (udst >= (uint8_t *) PHYS_BASE || !put_user (udst, input_getc())){
      if (!try_grow_stack(udst, esp)) sys_exit(-1);
    }
  }
}

/* Copies SIZE bytes from user address USRC to kernel address DST. Calls
   thread_exit() if any of the user accesses are invalid. */
static void copy_in (void *dst_, const void *usrc_, size_t size, void *esp){
  uint8_t *dst = dst_;
  uint8_t *usrc = (uint8_t *)usrc_;
  for (; size > 0; size--, dst++, usrc++){
    while(usrc >= (uint8_t *) PHYS_BASE || !get_user (dst, usrc)){
      if (!try_grow_stack(usrc, esp)) sys_exit(-1);
    }
  }
}

static char *copy_in_string (const char *us_, void *esp){
  char *ks;
  int i;
  char *us = (char *)us_;
  /* allocates a new single page ks */
  ks = palloc_get_page (0);
  if (ks == NULL)
    thread_exit ();

  for (i=0; i<PGSIZE; i++){
    while(us+i >= (const char *) PHYS_BASE || 
          !get_user ((uint8_t *)ks+i, (uint8_t *)us+i))
      {
        if (!try_grow_stack(us+i, esp)){
          palloc_free_page(ks);
          sys_exit(-1);
        }
      }      
    if (us[i] == '\0'){
      return ks;
    }
  }

  return ks;
}


typedef int (*handler_function)(int, int, int, int);

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
  {SYS_TELL, 1, (handler_function)tell}
};


#define num_handlers (sizeof(handlers) / sizeof(struct handler_entry))

static void syscall_handler (struct intr_frame *f){
  unsigned call_nr;
  copy_in (&call_nr, f->esp, sizeof call_nr, f->esp);

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
  int args[4]; //fourth arg is reserved for esp
  memset (args, 0, sizeof *args);

  copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * syscall.argc, f->esp);
  args[syscall.argc] = (int)f->esp;
  f->eax = syscall.func(args[0], args[1], args[2], args[3]);
}

void syscall_init (void){
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}


/* Write system call */
int sys_write (int handle, void *usrc_, unsigned size, void *esp){
  is_valid_pointer(usrc_);
  char *usrc = usrc_;
  int bytes; 
  if (handle == STDOUT_FILENO){
    putbuf (usrc, size);
    return size;
  }
  lock_acquire (&filesys_lock);
  struct file_descriptor *fd = lookup_fd(handle);
  if (!fd) {
    lock_release (&filesys_lock);
    sys_exit (-1);
  }
  bytes = file_write (fd->file, usrc, size);
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
pid_t sys_exec (const char *file_, void *esp){
  char *file = copy_in_string(file_, esp);
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
int sys_create (const char *file, unsigned initial_size, void *esp){
  char *kfile = copy_in_string (file, esp);
  lock_acquire (&filesys_lock);
  int create_try = filesys_create (kfile, initial_size);
  lock_release (&filesys_lock);
  palloc_free_page (kfile);
  return create_try;
}

/* Remove system call */
int sys_remove (const char *file, void *esp){
  char *kfile = copy_in_string (file, esp);
  int remove_try = filesys_remove (kfile);
  palloc_free_page (kfile);
  return remove_try;
}

/* Open system call */
int sys_open (const char *file, void *esp){
  char *kfile = copy_in_string (file, esp);
  lock_acquire (&filesys_lock);
  struct file *open_try = filesys_open (kfile);
  if (!open_try){
    lock_release (&filesys_lock);
    return -1;
  }
  struct file_descriptor *new_fd = (struct file_descriptor*) malloc (sizeof(struct file_descriptor));
  new_fd->handle = get_handle ();
  new_fd->file = open_try;
  struct thread *cur = thread_current();
  list_push_front(&cur->process->fd_list, &new_fd->elem);
  palloc_free_page (kfile);
  lock_release (&filesys_lock);
  return new_fd->handle;
}

int get_handle (){
  next_fd++;
  return next_fd;
}

/* Close system call */
void sys_close (int handle){
  if (handle < 2)
    sys_exit (-1); 
    lock_acquire (&filesys_lock); 
  struct file_descriptor *fd = lookup_fd (handle);
  if (fd){
    file_close (fd->file);
    list_remove (&fd->elem);
    free (fd);
  }
  lock_release (&filesys_lock);
}

/* Filesize system call */
int sys_filesize (int handle){
  lock_acquire (&filesys_lock);
  struct file_descriptor *fd = lookup_fd (handle);
  if (!fd){
    lock_release (&filesys_lock);
    sys_exit (-1);
  }
  int bytes = file_length (fd->file);
  lock_release (&filesys_lock);
  return bytes;
}

/* Read system call */
int sys_read (int handle, uint8_t *buffer, unsigned size, void *esp){
  if (handle == STDIN_FILENO){
    write_stdin(buffer, size, esp);
    return size;
  } 
  struct file_descriptor *fd = lookup_fd (handle);
  if (!fd) sys_exit (-1);

  void *kbuff = palloc_get_page(0);
  unsigned bytes = 0;
  while (bytes < size){
    int amount_to_read = size > PGSIZE ? PGSIZE : size;
    lock_acquire (&filesys_lock);
    int read = file_read (fd->file, kbuff, amount_to_read);
    lock_release (&filesys_lock);
    write_out(buffer + bytes, kbuff, read, esp);
    bytes += read;
    if (read < amount_to_read) break;
  }
  palloc_free_page(kbuff);
  return bytes;
}

/* Tell system call */
unsigned tell (int handle){
  lock_acquire (&filesys_lock);
  struct file_descriptor *fd = lookup_fd (handle);
  if (!fd){
    lock_release (&filesys_lock);
    sys_exit (-1);
  }
  struct file *f = fd->file;
  unsigned bytes = file_tell (f);
  lock_release (&filesys_lock);
  return bytes;
}

/* Seek system call */
void seek (int handle, unsigned position){
  lock_acquire (&filesys_lock);
  struct file_descriptor *fd = lookup_fd (handle);
  if (!fd){
    lock_release (&filesys_lock);
    sys_exit (-1);
  }
  struct file *f = fd->file;
  file_seek (f, position);
  lock_release (&filesys_lock);
}

/* Checks whether a user pointer is valid */
static void is_valid_pointer (const void *p){
  if (!p || !is_user_vaddr (p) ||  !pagedir_get_page (thread_current ()->pagedir, p)){
    sys_exit (-1);
  }
}

bool is_stack_access(void *vaddr, void *esp){
  return 
    is_user_vaddr(vaddr) && 
    (vaddr >= esp || 
     (vaddr + PUSH_BYTES) == esp || 
     (vaddr + PUSHA_BYTES) == esp);
}

/* 
   Grows stack if necessary. Returns true if stack was grown and false otherwise
 */
bool try_grow_stack(void *uaddr, void *esp){
  if (!is_stack_access(uaddr, esp)|| (PHYS_BASE - esp) > MAX_STACK_SZ)
    return false;
  return add_to_page_table(pg_round_down(uaddr), true) != NULL;
  
}
