#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/frame.h"

static thread_func start_process NO_RETURN;
static bool load (char *cmdline, void (**eip) (void), void **esp);
static void process_close_files(void);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *cmdline) 
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, cmdline, PGSIZE);
  char cmd_cpy[strlen(cmdline) + 1];
  strlcpy(cmd_cpy, cmdline, strlen(cmdline) + 1);
  char *args;
  char *file_name = strtok_r(cmd_cpy, " ", &args);
  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (file_name, PRI_DEFAULT, start_process, fn_copy);
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy);
  thread_add_child_process(tid);
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;
  struct thread *cur = thread_current();
  cur->is_processs = true;
  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  if (cur->process){
    cur->process->loaded = success;
    sema_up(&cur->process->sema_load);
  }

  /* If load failed, quit. */
  palloc_free_page (file_name);
  if (!success){  
    thread_exit ();
  }
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.
 */
int process_wait (tid_t child_tid) {
  struct process *p = thread_get_child_process(child_tid);
  if (!p) return -1;
  sema_down(&p->sema_exit);
  int status = p->exit_status;
  remove_and_free_process(p);
  return status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  process_remove_mmap (CLOSE_ALL);

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */

      spt_destroy(&cur->spt);
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
  lock_acquire(&filesys_lock);
  file_close(cur->process->executable);
  lock_release(&filesys_lock);
  process_close_files();
  /* Wakes up waiting parent */
  if (cur->process) sema_up(&cur->process->sema_exit);
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);
  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, char *cmdline);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (char *cmdline, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  //parse file name from cmdline
  char *args;
  char *file_name = strtok_r(cmdline, " ", &args);

  lock_acquire (&filesys_lock);
  file = filesys_open (file_name);
  lock_release (&filesys_lock);
  t->process->executable = file;
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }
  lock_acquire (&filesys_lock);
  file_deny_write(file);
  lock_release (&filesys_lock);
  /* Read and verify executable header. */
  lock_acquire (&filesys_lock);
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      lock_release (&filesys_lock);
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }
  lock_release (&filesys_lock);

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      lock_acquire (&filesys_lock);
      if (file_ofs < 0 || file_ofs > file_length (file)){
        lock_release (&filesys_lock);
        goto done;
      }

      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr){
        lock_release (&filesys_lock);
        goto done;
      }
      lock_release (&filesys_lock);
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  //restore cmdline before call to setup_stack
  if (*args != '\0')
      *(file_name + strlen(file_name)) = ' ';
  /* Set up stack. */  
  if (!setup_stack (esp, cmdline))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  return success;
}

/* load() helpers. */

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */

  lock_acquire (&filesys_lock);
  if (phdr->p_offset > (Elf32_Off) file_length (file)){
    lock_release (&filesys_lock);
    return false;
  }
  lock_release (&filesys_lock);

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);
  lock_acquire (&filesys_lock);
  file_seek (file, ofs);
  lock_release (&filesys_lock);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;
      
      /* Get a page of memory. */
      struct page *sp = add_to_page_table (upage, writable, FILE);
      if (sp == NULL)
        return false;

      sp->file = file;
      sp->offset = ofs;
      sp->read_bytes = page_read_bytes;
      sp->zero_bytes = page_zero_bytes;
      
      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      ofs += page_read_bytes;
      upage += PGSIZE;
    }
  return true;
}
// You need to put some data (args, pointers, etc.) to the stack/user page.
// Below is a wrapped memcopy helper function that you can use.
// It's a little bit complex, because it passes pointer by reference
// (i.e. pointer to pointer).
// Feel free to use your own implementation.
// Offset (ofs) will be automatically modified inside the push() function.
static void *
push (uint8_t *kpage, size_t *ofs, const void *buf, size_t size)
{
  size_t padsize = ROUND_UP (size, sizeof (uint32_t));
  if (*ofs < padsize)
    return NULL;

  *ofs -= padsize;
  memcpy (kpage + *ofs + (padsize - size), buf, size);
  return kpage + *ofs + (padsize - size);
}

/* Reverses the order of pointers on the stack.
   Used to put user_arg pointers in right to left order
*/
static void
reverse(void *stack, int num_args)
{
  void **start = stack;
  void **end = start + (num_args - 1);
  while(start < end){
    void *temp = *start;
    *start = *end;
    *end = temp;
    start++;
    end--;
  }
}

/* 
   Pushes argument stack 
   Returns pointer to top of the stack
*/
static void *
setup_args(uint8_t *upage, uint8_t *kpage, char *cmdline){
  size_t offs = PGSIZE;
  char *cmdline_cpy = push(kpage, &offs, cmdline, strlen(cmdline) + 1);

  int argc = 0;
  char *saveptr;
  char *parsed_arg = strtok_r(cmdline_cpy, " ", &saveptr);
  void *sentinel = NULL;
  push(kpage, &offs, &sentinel, sizeof sentinel);
  while (parsed_arg) {
    void *user_arg = upage + (parsed_arg - (char *) kpage);
    push (kpage, &offs, &user_arg, sizeof user_arg);
    parsed_arg = strtok_r(NULL, " ", &saveptr);
    argc++;
  }
  reverse(kpage + offs, argc); //rev addr pointers
  void * argv = upage + offs;
  push(kpage, &offs, &argv, sizeof argv);
  void *upage_addr = PHYS_BASE;
  push(kpage, &offs, &argc, sizeof argc); 
  push(kpage, &offs, &upage_addr, sizeof upage_addr);
  return upage + offs;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, char *cmdline)
{
  uint8_t *upage = ((uint8_t *) PHYS_BASE) - PGSIZE;
  struct page *stack_page = add_to_page_table (upage, true, MEMORY);
  if (!stack_page)
    return false;
  *esp = PHYS_BASE;
  if (strlen(cmdline) + 1 > PGSIZE) return NULL;
  page_lock(upage);
  *esp = setup_args(upage, page_physaddr(stack_page), cmdline);
  page_unlock(upage);
  return true;
}

static void
process_close_files(){
  struct thread *cur = thread_current();
  struct list_elem *e = list_begin (&cur->process->fd_list);
  struct list_elem *next_e;
  struct file_descriptor *fd;

  while (e != list_end (&cur->process->fd_list)){
    next_e = list_next (e);
    fd = list_entry (e, struct file_descriptor, elem);
    sys_close (fd->handle);
    e = next_e;
  }
}

bool process_add_mmap (struct page *sp){
  struct mmap_file *mf = (struct mmap_file *) malloc (sizeof (struct mmap_file));
  if (!mf)
    return false;
  mf->sp = sp;
  struct thread *cur = thread_current ();
  mf->id = cur->map_id;
  list_push_front (&cur->mmap_list, &mf->elem);
  return true;
}

void process_remove_mmap (int mapping){
  struct thread *cur = thread_current ();
  struct list_elem *e = list_begin (&cur->mmap_list);
  struct list_elem *next;
  struct file *file = NULL;
  int close = 0;
  struct mmap_file *mf;
  while (e != list_end (&cur->mmap_list)){
    next = list_next (e);
    mf = list_entry (e, struct mmap_file, elem);
    if (mf->id == mapping || mapping == CLOSE_ALL){
      struct file *sp_file = mf->sp->file;
      hash_delete (&cur->spt, &mf->sp->elem);
      deallocate_page(mf->sp);

      list_remove (&mf->elem);
      if (mf->id != close){
	if (file){
	  lock_acquire (&filesys_lock);
	  file_close (file);
	  lock_release (&filesys_lock);
	}
	close = mf->id;
	file = sp_file;
      }
      free (mf);
    }
    e = next;
  }
  if (file){
    lock_acquire (&filesys_lock);
    file_close (file);
    lock_release (&filesys_lock);
  }
}
