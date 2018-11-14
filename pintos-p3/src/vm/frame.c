#include "vm/frame.h"
#include <stdlib.h>
#include <string.h>
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/loader.h"


static struct frame *frames;
static size_t frame_cnt;

static struct lock scan_lock;
static size_t hand;

static struct frame *find_free_frame(void);

void
frame_init ()
{
  void *base;

  lock_init (&scan_lock);

  frames = malloc (sizeof *frames * init_ram_pages);
  if (frames == NULL)
    PANIC ("out of memory allocating page frames");

  while ((base = palloc_get_page (PAL_USER)) != NULL)
    {
      struct frame *f = &frames[frame_cnt++];
      lock_init (&f->lock);
      f->base = base;
      f->page = NULL;
    }
}

/* Finds a frame in frames that is not yet tied to a page and returns
   it. Linear search for now.
 */
static struct frame *find_free_frame(){
  struct frame *frame = NULL;
  lock_acquire(&scan_lock);
  unsigned i;
  for(i = 0; i < frame_cnt; i++){
    if (frames[i].page == NULL){
      frame = &frames[i];
      break;
    }
  }
  lock_release(&scan_lock);
  return frame;
}

/* Tries to allocate and lock a frame for PAGE.
   Returns the frame if successful, false on failure. */
static struct frame *try_frame_alloc_and_lock (struct page *page) {
  struct frame *frame = find_free_frame();
  if (frame == NULL) return NULL;
  frame->page = page;
  lock_acquire(&frame->lock);
  return frame;
}

/* 
   Tries really hard to allocate and lock a frame for PAGE.
   Returns the frame if successful, false on failure. 
*/
struct frame *frame_alloc_and_lock (struct page *page) {
  struct frame *frame = try_frame_alloc_and_lock(page);
  if (frame == NULL) {
    //perform swap before giving up
    return NULL;
  }
  return frame;
}

/* Fills physical frame with zeros */
void frame_fill_zeros(struct frame *f){
  memset(f->base, 0, PGSIZE);
}
/* Locks P's frame into memory, if it has one.
   Upon return, p->frame will not change until P is unlocked. */
void frame_lock (struct page *p) {
  if (p->frame)
    lock_acquire(&p->frame->lock);
}

/* Releases frame F for use by another page.
   F must be locked for use by the current process.
   Any data in F is lost. */
void frame_free (struct frame *f) {
  ASSERT(lock_held_by_current_thread(&f->lock));
  f->page = NULL;
  lock_release(&f->lock);
}

/* Unlocks frame F, allowing it to be evicted.
   F must be locked for use by the current process. */
void frame_unlock (struct frame *f) {
  ASSERT(lock_held_by_current_thread(&f->lock));
  lock_release(&f->lock);
}

