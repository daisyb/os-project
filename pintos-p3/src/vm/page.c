#include "vm/swap.h"
#include <stdio.h>
/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from theuser pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
bool install_page (struct page *p, bool writable){
  /* Verify that ther's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (p->pagedir, p->vaddr) == NULL
	  && pagedir_set_page (p->pagedir, p->vaddr, page_physaddr(p), writable));
}

/*
 removes UPAGE from page table
*/
static void uninstall_page(struct page *p){
  pagedir_clear_page(p->pagedir, p->vaddr);
}

unsigned page_hash (const struct hash_elem *e, void *aux UNUSED){
  const struct page *sp = hash_entry (e, struct page, elem);
  unsigned result = hash_bytes (&sp->vaddr, sizeof (sp->vaddr));
  return result;
}

bool page_less (const struct hash_elem *e1, const struct hash_elem *e2, void *aux UNUSED){
  const struct page *sp1 = hash_entry (e1, struct page, elem);
  const struct page *sp2 = hash_entry (e2, struct page, elem);
  bool result = sp1->vaddr < sp2->vaddr;
  return result;
}

void spt_init (struct hash *spt){
  hash_init (spt, page_hash, page_less, NULL);
}

void deallocate_page(struct page *p){
  if (!p) return;
  lock_acquire(&p->lock);
  if (p->type == SWAP){
    swap_free_slot(p->swap_index);
  }
  if (p->frame){
    frame_lock(p->frame);
    if (p->type == MMAP && page_is_dirty(p)){
      mmap_write(p);
    }
    frame_free(p->frame);
  }
  uninstall_page(p);
  lock_release(&p->lock);
  free(p);
}

/* Destroys a page, which must be in the current process's
   page table.  Used as a callback for hash_destroy(). */
static void destroy_page (struct hash_elem *p_, void *aux UNUSED)
{
  struct page *sp = hash_entry (p_, struct page, elem);
  deallocate_page(sp);
}

/* Destroys the current process's supp page table. */
void spt_destroy (struct hash *spt){
  hash_destroy(spt, destroy_page);
}

struct page *get_sp (void *vaddr){
  struct page sp;
  sp.vaddr = pg_round_down (vaddr);
  struct thread *cur = thread_current ();
  struct hash_elem *e = hash_find (&cur->spt, &sp.elem);
  if (!e){
    return NULL;
  }
  return hash_entry (e, struct page, elem);
}

bool load_page (struct page *sp){
  bool success = false;
  switch (sp->type){
  case FILE:
  case MMAP:
    success = load_file (sp);
    break;
  case SWAP:
    success = load_swap (sp);
    if (success) sp->type = MEMORY;
    break;
  case MEMORY:
    success = load_memory(sp);
  }
  if (success && install_page(sp, sp->writable)){
    frame_unlock(sp->frame);
  } else if (sp->frame){
    frame_free(sp->frame);
    success = false;
  }
  return success;
}

bool load_swap (struct page *sp){
  struct frame *frame = frame_alloc_and_lock(sp);
  return frame && swap_in (sp);
}

bool load_memory(struct page *sp){
  struct frame *frame = frame_alloc_and_lock (sp);
  return frame;
}
bool load_file (struct page *sp){
  struct frame *frame = frame_alloc_and_lock (sp);
  if (!frame) return false;
  if (sp->read_bytes > 0){
    lock_acquire (&filesys_lock);
    if ((int) sp->read_bytes != file_read_at (sp->file, frame->base, sp->read_bytes, sp->offset)){
      lock_release (&filesys_lock);
      return false;
    }
    lock_release (&filesys_lock);
  }
  memset (frame->base + sp->read_bytes, 0, sp->zero_bytes);
  return true;
}

struct page *add_to_page_table (uint8_t *upage, bool writable, int type){
  struct page *sp;
  if((sp = get_sp(upage))) return NULL;
  sp = malloc (sizeof (struct page));
  if (!sp)
    return NULL;
  sp->vaddr = pg_round_down(upage);
  sp->type = type;
  sp->writable = writable;
  sp->frame = NULL;
  lock_init(&sp->lock);
  sp->pagedir = thread_current()->pagedir;
  hash_insert (&(thread_current ()->spt), &sp->elem);
  if (type == MEMORY) load_page(sp);
  return sp;
}

bool mmap_write(struct page *p){
  ASSERT(frame_lock_held_by_current_thread(p));
  if (p->read_bytes > 0){
    lock_acquire (&filesys_lock);
    if ((int) p->read_bytes != file_write_at (p->file, page_physaddr(p), p->read_bytes, p->offset)){
      lock_release (&filesys_lock);
      return false;
    }
    lock_release (&filesys_lock);
  }
  return true;

}

/* Evicts page P.
   P must have a locked frame.
   Return true if successful, false on failure. */
bool page_out (struct page *p){
  ASSERT(frame_lock_held_by_current_thread(p));
  lock_acquire(&p->lock);
  int success = true;
  int swap = true;
  switch(p->type){
  case MMAP:
    if (page_is_dirty(p))
      success = mmap_write(p);
    swap = false;
    break;
  case FILE:
    swap = page_is_dirty(p);
    break;
  }
  if (swap){
    success = swap_out(p);
    p->type = SWAP;
  }
  uninstall_page(p);
  p->frame = NULL;
  lock_release(&p->lock);
  return success;
}

/* Trys to add page containing FAULT_ADDR to memory.
   Returns true if successful, false on failure. */
bool page_in (void *fault_addr){
  struct page *p = get_sp(fault_addr);
  return p && load_page(p);
}

bool page_present(void *addr){
  return get_sp(addr) != NULL;
}

bool page_is_writable(void *addr){
  struct page *p = get_sp(addr);
  return p && p->writable;
}

bool page_accessed_recently (struct page *p) {
  return pagedir_is_accessed(p->pagedir, p->vaddr);
}

void page_clear_accessed(struct page *p){
  pagedir_set_accessed(p->pagedir, p->vaddr, false);
}

bool page_is_dirty(struct page *p){
  return pagedir_is_dirty(p->pagedir, p->vaddr);
}  

bool page_lock (void *addr){
  struct page *p = get_sp(addr);
  if (!p) return false;
  if (!p->frame){
    if (!load_page(p)) return false;
  }
  frame_lock(p->frame);
  return true;
}
void page_unlock (void *addr) {
  struct page *p = get_sp(addr);
  frame_unlock(p->frame);
}

void *page_physaddr(struct page *p){
  if(!p || !p->frame) return NULL;
  return p->frame->base;
}
