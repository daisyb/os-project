
#include <debug.h>
#include <string.h>
#include <stdio.h>
#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "threads/thread.h"

static int hand;

static void cache_block_lock(struct cache_block *b);
static bool cache_block_try_lock(struct cache_block *b);

void cache_init (void){
  int i;
  for (i=0; i<CACHE_CNT; i++){
    cache[i].sector = INVALID_SECTOR;
    lock_init(&cache[i].block_lock);
  }
  lock_init (&cache_lock);
  hand = 0;
}

struct cache_block *lookup_block (block_sector_t sector){
  struct cache_block *b = NULL;
  int i;
  lock_acquire(&cache_lock);
  for (i=0; i<CACHE_CNT; i++){
    if (cache[i].sector == sector){
      b = &cache[i];
      cache_block_lock(b);
      break;
    }
  }
  lock_release(&cache_lock);
  return b;
}

struct cache_block *cache_evict (void){
  struct cache_block *b = NULL;
  lock_acquire(&cache_lock);
  int i;
  for (i=0; i<CACHE_CNT; i++){
    if (cache[i].sector == INVALID_SECTOR){
      b =  &cache[i];
      cache_block_lock(b);
      break;
    }
  }
  struct cache_block *cur = NULL;
  while(!b){
    cur = &cache[hand++];
    if (!cur->clock_bit && cache_block_try_lock(cur)){
      b = cur;
    } else {
      cur->clock_bit = false;
    }
    if (hand >= CACHE_CNT)
      hand = 0;
  }
  lock_release(&cache_lock);
  if (b->dirty && b->sector != INVALID_SECTOR)
    block_write (fs_device, b->sector, b->data);
  return b;
}

void cache_fill (struct cache_block *b, block_sector_t sector){
  b->sector = sector;
  block_read (fs_device, sector, b->data);
  b->dirty = false;
  b->clock_bit = true;
}

struct cache_block *get_block (block_sector_t sector){
  struct cache_block *b = lookup_block (sector);
  if (b){
    b->clock_bit = true;
    return b;
  }
  b = cache_evict ();
  if (!b)
    PANIC ("Buffer cache failure.");
  cache_fill (b, sector);
  return b;
}

/* Marks block B as dirty, so that it will be written back to
   disk before eviction.
   The caller must have a read or write lock on B,
   and B must be up-to-date. */
void
cache_dirty (struct cache_block *b)
{
  ASSERT(lock_held_by_current_thread(&b->block_lock));
  b->dirty = true;
}

static void cache_block_lock(struct cache_block *b){
  lock_acquire(&b->block_lock);  
}

UNUSED static bool cache_block_try_lock(struct cache_block *b){
  return lock_try_acquire(&b->block_lock);
}

void cache_unlock(struct cache_block *b){
  ASSERT(lock_held_by_current_thread(&b->block_lock));
  lock_release(&b->block_lock);  
}

void cache_flush (void){
  lock_acquire (&cache_lock);
  struct cache_block *b;
  int i;
  for (i=0; i<CACHE_CNT; i++){
    b = &cache[i];
    if (b->dirty)
      block_write (fs_device, b->sector, b->data);
    b->sector = INVALID_SECTOR;
  }
  lock_release (&cache_lock);
}
