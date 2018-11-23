#include "swap.h"
#include <bitmap.h>
#include "devices/block.h"
#include <stdio.h>
/*

Managing the swap table

You should handle picking an unused swap slot for evicting a page from its
frame to the swap partition. And handle freeing a swap slot which its page
is read back.

You can use the BLOCK_SWAP block device for swapping, obtaining the struct
block that represents it by calling block_get_role(). Also to attach a swap
disk, please see the documentation.

and to attach a swap disk for a single run, use this option â€˜--swap-size=nâ€™

*/




// we just provide swap_init() for swap.c
// the rest is your responsibility

/* The swap device. */
static struct block *swap_device;

/* Used swap pages. */
static struct bitmap *swap_bitmap;

/* Protects swap_bitmap. */
static struct lock swap_lock;

/* Number of sectors per page. */
#define PAGE_SECTORS (PGSIZE / BLOCK_SECTOR_SIZE)

/* Set up*/
void
swap_init (void)
{
  swap_device = block_get_role (BLOCK_SWAP);
  if (swap_device == NULL)
    {
      printf ("no swap device--swap disabled\n");
      swap_bitmap = bitmap_create (0);
    }
  else
    swap_bitmap = bitmap_create (block_size (swap_device)
                                 / PAGE_SECTORS);
  if (swap_bitmap == NULL)
    PANIC ("couldn't create swap bitmap");
  lock_init (&swap_lock);
}

void swap_free_slot(size_t swap_index){
  bitmap_reset(swap_bitmap, swap_index / 8);
}

/* Swaps in page P, which must have a locked frame
   (and be swapped out). */
bool
swap_in (struct page *p)
{
  ASSERT(p->frame != NULL);
  ASSERT(frame_lock_held_by_current_thread(p));
  lock_acquire(&swap_lock);
  if (!bitmap_test(swap_bitmap, p->swap_index / 8)) return false;
  void *frame_addr = page_physaddr(p);
  unsigned i;
  for (i = p->swap_index; i < p->swap_index + 8; i++, frame_addr += BLOCK_SECTOR_SIZE){
    block_read(swap_device, i, frame_addr);
  }
  swap_free_slot(p->swap_index);
  lock_release(&swap_lock);
  return true;
}

/* Swaps out page P, which must have a locked frame. */
bool 
swap_out (struct page *p) 
{
  ASSERT(p->frame != NULL);
  ASSERT(frame_lock_held_by_current_thread(p));
  lock_acquire(&swap_lock);
  size_t sector = bitmap_scan_and_flip(swap_bitmap, 0, 1, 0);
  if (sector == BITMAP_ERROR){
    lock_release(&swap_lock);
    PANIC("Swap space is full");
  }
  p->swap_index = sector * 8;
  void *frame_addr = page_physaddr(p);
  unsigned i;
  for(i = p->swap_index; i < p->swap_index + 8; i++, frame_addr += BLOCK_SECTOR_SIZE){
    block_write(swap_device, i, frame_addr);
  }
  lock_release(&swap_lock);
  return true;
}
