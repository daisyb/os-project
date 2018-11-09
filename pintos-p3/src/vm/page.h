#include <stdbool.h>
#include <debug.h>
#include "lib/kernel/hash.h"
#define STACK_MAX (1024 * 1024)

struct page {

};

/* Destroys a page, which must be in the current process's
   page table.  Used as a callback for hash_destroy(). */
static void destroy_page (struct hash_elem *p_, void *aux UNUSED);
/* Destroys the current process's page table. */
void page_exit (void);
/* Returns the page containing the given virtual ADDRESS,
   or a null pointer if no such page exists.
   Allocates stack pages as necessary. */
static struct page *page_for_addr (const void *address);
/* Locks a frame for page P and pages it in.
   Returns true if successful, false on failure. */
static bool do_page_in (struct page *p);
/* Faults in the page containing FAULT_ADDR.
   Returns true if successful, false on failure. */
bool page_in (void *fault_addr);
/* Evicts page P.
   P must have a locked frame.
   Return true if successful, false on failure. */
bool page_out (struct page *p);
/* Returns true if page P's data has been accessed recently,
   false otherwise.
   P must have a frame locked into memory. */
bool page_accessed_recently (struct page *p);
/* Adds a mapping for user virtual address VADDR to the page hash
   table.  Fails if VADDR is already mapped or if memory
   allocation fails. */
struct page * page_allocate (void *vaddr, bool read_only);
/* Evicts the page containing address VADDR
   and removes it from the page table. */
void page_deallocate (void *vaddr);
/* Returns a hash value for the page that E refers to. */
unsigned page_hash (const struct hash_elem *e, void *aux UNUSED);
/* Returns true if page A precedes page B. */
bool page_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);
/* Tries to lock the page containing ADDR into physical memory.
   If WILL_WRITE is true, the page must be writeable;
   otherwise it may be read-only.
   Returns true if successful, false on failure. */
bool page_lock (const void *addr, bool will_write);
/* Unlocks a page locked with page_lock(). */
void page_unlock (const void *addr);

