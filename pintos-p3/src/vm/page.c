#include "vm/page.h"

unsigned page_hash (const struct hash_elem *e, void *aux UNUSED){
  const struct supp_page *sp = hash_entry (e, struct supp_page, elem);
  return hash_bytes (&p->vaddr, sizeof p->vaddr);
}

bool page_less (const struct hash_elem *e1, const struct hash_elem *e2, void *aux UNUSED){
  const struct supp_page *sp1 = hash_entry (e1, struct supp_page, elem);
  const struct supp_page *sp2 = hash_entry (e2, struct supp_page, elem);
  return p1->vaddr < p2->vaddr;
}

static void page_action (struct hash_elem *e, void *aux UNUSED){
  struct supp_page *sp = hash_entry (e, struct supp_page, elem);
  if (sp->is_loaded){
    frame_free (pagedir_get_page (thread_current()->pagedir, sp->vaddr));
    pagedir_clear_page (thread_current()->pagedir, sp->vaddr);
  }
  free (sp);
}

void spt_init (struct hash *spt){
  hash_init (spt, page_hash, page_less, NULL);
}

void spt_destroy (struct hash *spt){
  hash_destroy (spt, page_action);
  /* Should this also make use of destroy_page? */
}

struct supp_page *get_sp (void *vaddr){
  struct supp_page sp;
  sp.vaddr = pg_round_down (vaddr);

  struct hash_elem *e = hash_find (&thread_current()->spt, &sp.elem);
  if (!e){
    return NULL;
  }
  return hash_entry (e, struct supp_page, elem);
}

bool load_page (struct supp_page *sp){
  bool success = false;
  sp->busy = true;
  if (sp->is_loaded){
    return success;
  }
  switch (sp->type){
  case FILE:
    success = load_file (sp);
    break;
  case SWAP:
    success = load_swap (sp);
    break;
  }
  return success;
}

bool load_swap (struct supp_page *sp){
  uint8_t *frame = frame_alloc (PAL_USER, sp);
  if (!frame){
    return false;
  }
  if (!install_page (sp->vaddr, frame, sp->writable)){
    frame_free (frame);
    return false;
  }
  swap_in (sp->swap_index, sp->vaddr);
  sp->is_loaded = true;
  return true;
}

bool load_file (struct supp_page *sp){
  enum palloc_flags flags = PAL_USER;
  if (sp->read_bytes == 0){
    flags |= PAL_ZERO;
  }
  uint8_t *frame = frame_alloc (flags, sp);
  if (!frame){
    return false;
  }
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
}

bool add_file_to_page_table (struct file *file, int32_t ofs, uint8_t *upage, uint32_t read_bytes, /*uint32_t zero_bytes, */bool writable){
  struct supp_page *sp = malloc (sizeof (struct supp_page));
  if (!sp){
    return false;
  }
  sp->file = file;
  sp->offset = ofs;
  sp->vaddr = upage;
  sp->read_bytes = read_bytes;
  //sp->zero_bytes = zero_bytes;
  sp->writable = writable;
  //sp->is_loaded = false;
  sp->type = FILE;
  sp->busy = false;
  return (hash_insert (&thread_current()->spt, &sp->elem) == NULL);
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
