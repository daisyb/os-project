#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "threads/thread.h"

static int cache_size;

/* Initializes cache */
void cache_init (void){
  list_init (&cache);
  lock_init (&cache_lock);
  cache_size = 0;
}

/* Searches cache for block with sector SECTOR. Returns the block if it exists, null otherwise. */
struct cache_block *lookup_block (block_sector_t sector){
  struct list_elem *e;
  struct cache_block *b;
  for (e = list_begin (&cache);
       e != list_end (&cache);
       e = list_next (e)){
    b = list_entry (e, struct cache_block, elem);
    if (b->sector == sector)
      return b;
  }
  return NULL;
}

/* Retrieves a block from cache for use by SECTOR. */
struct cache_block *get_block (block_sector_t sector){
  lock_acquire (&cache_lock);
  struct cache_block *b = lookup_block (sector);
  if (b)
    goto done;
  b = cache_evict ();
  cache_fill (b, sector);
  if (b)
    goto done;
  PANIC ("Buffer cache failure.");
 done:
  lock_release (&cache_lock);
  return b;
}

struct cache_block *cache_evict (void){
  struct cache_block *b = NULL;
  /* Room to simply create a new cache_block */
  if (cache_size < 65){
    b = (struct cache_block *) malloc (sizeof (struct cache_block));
    if (!b)
      return NULL;
    list_push_back (&cache, &b->elem);
    cache_size++;
  }
  /* We need to evict a block -- currently implemented using simple clock */
  /* Problem I thought of: using the list struct really messes with the circular nature of the clock design. Entries toward the front will get decremented a lot more often, but I can't tell if this will be a problem or not. */
  else {
    struct list_elem *e;
    for (e = list_begin (&cache);
	 e != list_end (&cache);
	 e = list_next (e)){
      b = list_entry (e, struct cache_block, elem);
      if (b->clock_bit)
	b->clock_bit = false;
      else {
	if (b->dirty){
	  block_write (fs_device, b->sector, &b->data);
	}
      }
    }
  }
  return b;
}

void cache_fill (struct cache_block *b, block_sector_t sector){
  b->sector = sector;
  block_read (fs_device, sector, &b->data);
  b->dirty = false;
  b->clock_bit = true;
}

void cache_flush (void){
  lock_acquire (&cache_lock);
  struct list_elem *next;
  struct list_elem *e = list_begin (&cache);
  struct cache_block *b;
  while (e != list_end (&cache)){
    next = list_next (e);
    b = list_entry (e, struct cache_block, elem);
    if (b->dirty){
      block_write (fs_device, b->sector, &b->data);
      b->dirty = false;
    }
    list_remove (&b->elem);
    free (b);
    e = next;
  }
  lock_release (&cache_lock);
}
