//#include <stdbool.h>
//#include <stdlib.h>
//#include <debug.h>
#include "lib/kernel/hash.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include <string.h>
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "userprog/syscall.h"
#include "threads/interrupt.h"
#include "filesys/file.h"

#define FILE 0
#define SWAP 1
#define MEMORY 2

#define STACK_MAX (1024 * 1024)

struct page {
  void *vaddr;
  struct frame *frame;
  uint8_t type;
  bool writable;
  bool is_loaded;
  bool busy;
  

  /* Data only relevant to files */
  struct file *file;
  size_t offset;
  size_t read_bytes;
  size_t zero_bytes;

  /* Data only relevant to swaps */
  size_t swap_index;

  struct hash_elem elem;
};

/* Returns a hash value for the page that E refers to. */
unsigned page_hash (const struct hash_elem *e, void *aux UNUSED);

/* Returns true if page A precedes page B. */
bool page_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);

void spt_init (struct hash *spt);
void spt_destroy (struct hash *spt);
struct page *get_sp (void *vaddr);
bool load_page (struct page *sp);
bool load_swap (struct page *sp);
bool load_file (struct page *sp);
bool load_memory(struct page *sp);
//struct page *add_to_page_tablee (uint8_t *upage, bool writable, int type);
struct page *add_to_page_table (uint8_t *upage, bool writable, int type);
bool page_in(void *fault_addr);
bool page_out(struct page *p);
bool page_accessed_recently (struct page *p);
void page_clear_accessed(struct page *p);
bool page_lock (void *addr);
void page_unlock (void *addr);
void *page_physaddr(struct page *p);
/* Destroys a page, which must be in the current process's
   page table.  Used as a callback for hash_destroy(). */
//static void destroy_page (struct hash_elem *p_, void *aux UNUSED);

/* Destroys the current process's page table. */
//void page_exit (void);

/* Evicts the page containing address VADDR
   and removes it from the page table. */
//void page_deallocate (void *vaddr){

/* Returns true if page P's data has been accessed recently,
   false otherwise.
   P must have a frame locked into memory. */


/* Adds a mapping for user virtual address VADDR to the page hash
   table.  Fails if VADDR is already mapped or if memory
   allocation fails. */
//struct page * page_allocate (void *vaddr, bool read_only);

/* Evicts the page containing address VADDR
   and removes it from the page table. */
//void page_deallocate (void *vaddr);

/* Tries to lock the page containing ADDR into physical memory.
   If WILL_WRITE is true, the page must be writeable;
   otherwise it may be read-only.
   Returns true if successful, false on failure. */
//bool page_lock (const void *addr, bool will_write);

/* Unlocks a page locked with page_lock(). */
//void page_unlock (const void *addr);

