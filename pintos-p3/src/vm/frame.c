#include "vm/frame.h"
#include <stdlib.h>
#include <string.h>
#include <random.h>
#include <stdio.h>
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/loader.h"

static struct frame *frames;
static size_t frame_cnt;

static struct lock scan_lock;
static size_t hand;

static struct frame *find_free_frame(void);
static struct frame *evict_frame(void);

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
  unsigned i;
  for(i = 0; i < frame_cnt; i++){
    if (frames[i].page == NULL){
      return &frames[i];
    }
  }
  return NULL;
}

/*
Chooses a frame to evict and then evicts it
*/
static struct frame *evict_frame(){
  int frame_idx = random_ulong() % frame_cnt;
  lock_acquire(&scan_lock);
  struct frame *f = &frames[frame_idx];
  lock_release(&scan_lock);
  if (!page_out(f->page)) return NULL;
  return f;
}

/* Tries to allocate and lock a frame for PAGE.
   Returns the frame if successful, false on failure. */
static struct frame *try_frame_alloc_and_lock (struct page *page) {
  lock_acquire(&scan_lock);
  struct frame *frame = find_free_frame();
  if (frame == NULL) {
    lock_release(&scan_lock);
    return NULL;
  }
  frame->page = page;
  lock_release(&scan_lock);
  lock_acquire(&frame->lock);
  memset(frame->base, 0, PGSIZE);
  return frame;
}

/* 
   Tries really hard to allocate and lock a frame for PAGE.
   Returns the frame if successful, false on failure. 
*/
struct frame *frame_alloc_and_lock (struct page *page) {
  struct frame *frame = try_frame_alloc_and_lock(page);
  if (frame == NULL){
    frame = evict_frame();
  }
  return frame;
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

bool frame_lock_held_by_current_thread(struct page *p){
  return lock_held_by_current_thread(&p->frame->lock);
}
