#include "vm/frame.h"
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
bool install_page (void *upage, void *kpage, bool writable){
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

struct page *get_sp (void *vaddr){
  struct page sp;
  sp.vaddr = pg_round_down (vaddr);
  struct thread *cur = thread_current ();
  struct hash_elem *e = hash_find (&cur->spt, &sp.elem);
  if (!e)
    return NULL;
  return hash_entry (e, struct page, elem);
}

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
  hash_insert (&(thread_current ()->spt), &sp->elem);
  return sp;
}

struct page *add_mmap_to_page_table (struct file *file, int32_t ofs, uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes){
  struct page *sp = (struct page *) malloc (sizeof (struct page));
  if (!sp)
    return NULL;
  sp->file = file;
  sp->offset = ofs;
  sp->vaddr = upage;
  sp->read_bytes = read_bytes;
  sp->zero_bytes = zero_bytes;
  sp->writable = true;
  sp->is_loaded = false;
  sp->type = MMAP;
  if (!process_add_mmap (sp)){
    free (sp);
    return NULL;
  }
  struct thread *cur = thread_current ();
  if (hash_insert (&cur->spt, &sp->elem)){
    sp->type = HASH_ERROR;
    return NULL;
  }
  return sp;
}
