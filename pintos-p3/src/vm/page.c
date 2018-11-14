#include "vm/frame.h"

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from theuser pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool install_page (void *upage, void *kpage, bool writable){
  struct thread *t = thread_current ();
  /* Verify that ther's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
	  && pagedir_set_page (t->pagedir, upage, kpage, writable));
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

/*void spt_destroy (struct hash *spt){
  hash_destroy (spt, page_action);
}*/

struct page *get_sp (void *vaddr){
  struct page sp;
  sp.vaddr = pg_round_down (vaddr);

  struct hash_elem *e = hash_find (&(thread_current()->spt), &sp.elem);
  if (!e){
    return NULL;
  }
  return hash_entry (e, struct page, elem);
}

bool load_page (struct page *sp){
  bool success = false;
  sp->busy = true;
  if (sp->is_loaded){
    return success;
  }
  switch (sp->type){
    /*case FILE:
    success = load_file (sp);
    break;*/
    /*case SWAP:
    success = load_swap (sp);
    break;*/
  }
  return success;
}

/*bool load_swap (struct page *sp){
  struct frame *frame = frame_alloc_and_lock (sp);
  if (!frame){
    return false;
  }
  if (!install_page (sp->vaddr, frame, sp->writable)){
    frame_free (frame);
    return false;
  }
  //swap_in (sp->swap_index, sp->vaddr);
  sp->is_loaded = true;
  return true;
  }*/

/*bool load_file (struct page *sp){
  if (sp->read_bytes > 0){
    lock_acquire (&filesys_lock);
    if ((int) sp->read_bytes != file_read_at (sp->file, frame, sp->read_bytes, sp->offset)){
      lock_release (&filesys_lock);
      frame_free (frame);
      return false;
    }
    lock_release (&filesys_lock);
    memset (frame + sp->read_bytes, 0, sp->zero_bytes);
  }
  if (!install_page (sp->vaddr, frame, sp->writable)){
    frame_free (frame);
    return false;
  }
  sp->is_loaded = true;
  return true;
  }*/

struct page *add_to_page_table (uint8_t *upage, bool writable){
  struct page *sp = malloc (sizeof (struct page));
  if (!sp)
    return NULL;
  sp->vaddr = upage;

  struct frame *frame = frame_alloc_and_lock (sp);
  if (!frame){
    free (sp);
    return NULL;
  }
  sp->frame = frame;

  if (!install_page (upage, frame->base, writable)){
    frame_free (frame);
    free (sp);
    return NULL;
  }
  if (!(hash_insert (&(thread_current ()->spt), &sp->elem) == NULL)){
    free(sp);
    return NULL;
  }
  return sp;
}

/* static void destroy_page (struct hash_elem *p_, void *aux UNUSED)  {}
void page_exit (void)  {}
static struct page *page_for_addr (const void *address) {
  return NULL;
}
static bool do_page_in (struct page *p) {
  return true;
}
bool page_in (void *fault_addr) {
  return true;
}
bool page_out (struct page *p) {
  return true;
}
bool page_accessed_recently (struct page *p) {
  return true;
}
struct page * page_allocate (void *vaddr, bool read_only) {
  return NULL;
}
void page_deallocate (void *vaddr) {}
bool page_lock (const void *addr, bool will_write) {
  return true;
}
void page_unlock (const void *addr) {}
*/
