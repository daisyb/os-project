#include "vm/page.h"
#include "threads/synch.h"
/*
Managing the frame table

The main job is to obtain a free frame to map a page to. To do so:

1. Easy situation is there is a free frame in frame table and it can be
obtained. If there is no free frame, you need to choose a frame to evict
using your page replacement algorithm based on setting accessed and dirty
bits for each page. See section 4.1.5.1 and A.7.3 to know details of
replacement algorithm(accessed and dirty bits) If no frame can be evicted
without allocating a swap slot and swap is full, you should panic the
kernel.

2. remove references from any page table that refers to.

3.write the page to file system or swap.

*/


struct frame {
  void *base;
  struct page *page;
  struct lock lock;
};
void frame_init(void);

struct frame *frame_alloc_and_lock(struct page *p);
void frame_lock (struct frame *f);
void frame_free (struct frame *f);
void frame_unlock (struct frame *f);
bool frame_lock_held_by_current_thread(struct page *p);
