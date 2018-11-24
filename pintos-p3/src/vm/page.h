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
#define MMAP 1
#define SWAP 2
#define MEMORY 3
#define HASH_ERROR 2

#define STACK_MAX (1024 * 1024)

struct page {
  void *vaddr;
  struct frame *frame;
  uint8_t type;
  bool writable;
  uint32_t *pagedir;
  bool is_loaded;

  /* Data only relevant to files */
  struct file *file;
  size_t offset;
  size_t read_bytes;
  size_t zero_bytes;

  /* Data only relevant to swaps */
  size_t swap_index;

  struct hash_elem elem;
};

bool install_page (struct page *p, bool writable);
/* Returns a hash value for the page that E refers to. */
unsigned page_hash (const struct hash_elem *e, void *aux UNUSED);

/* Returns true if page A precedes page B. */
bool page_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);

void spt_init (struct hash *spt);
void spt_destroy (struct hash *spt);
struct page *get_sp (void *vaddr);
bool load_page (struct page *sp);
bool load_swap (struct page *sp);
//struct page *add_to_page_table (uint8_t *upage, bool writable);
struct page *add_mmap_to_page_table (struct file *file, int32_t ofs, uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes);
bool load_file (struct page *sp);
bool load_memory(struct page *sp);
//struct page *add_to_page_tablee (uint8_t *upage, bool writable, int type);
struct page *add_to_page_table (uint8_t *upage, bool writable, int type);
bool page_in(void *fault_addr);
bool page_out(struct page *p);
bool page_accessed_recently (struct page *p);
void page_clear_accessed(struct page *p);
bool page_is_dirty(struct page *p);
bool page_lock (void *addr);
void page_unlock (void *addr);
void *page_physaddr(struct page *p);
bool page_present(void *addr);
bool page_is_writable(void *addr);
