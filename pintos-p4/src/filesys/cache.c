#include <debug.h>
#include <string.h>
#include <stdio.h>
#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "threads/thread.h"

void cache_init (void){
  int i;
  for (i=0; i<CACHE_CNT; i++){
    cache[i].sector = INVALID_SECTOR;
  }
  lock_init (&cache_lock);
}

struct cache_block *lookup_block (block_sector_t sector){
  struct cache_block *b;
  int i;
  for (i=0; i<CACHE_CNT; i++){
    b = &cache[i];
    if (b->sector == sector){
      return b;
    }
  }
  return NULL;
}

struct cache_block *cache_evict (void){
  struct cache_block *b = NULL;
  int i;
  for (i=0; i<CACHE_CNT; i++){
    b = &cache[i];
    if (b->sector == INVALID_SECTOR)
      return b;
  }
  for (i=0; i<CACHE_CNT; i++){
    b = &cache[i];
    if (b->clock_bit)
      b->clock_bit = false;
    else {
      if (b->dirty)
	block_write (fs_device, b->sector, b->data);
      return b;
    }
  }
  if (b->dirty)
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
  lock_acquire (&cache_lock);
  struct cache_block *b = lookup_block (sector);
  if (b){
    b->clock_bit = true;
    lock_release (&cache_lock);
    return b;
  }
  b = cache_evict ();
  cache_fill (b, sector);
  
  if (!b)
    PANIC ("Buffer cache failure.");
  lock_release (&cache_lock);
  return b;
}

void cache_flush (void){
  lock_acquire (&cache_lock);
  struct cache_block *b;
  int i;
  for (i=0; i<CACHE_CNT; i++){
    b = &cache[i];
    if (b->dirty)
      block_write (fs_device, b->sector, b->data);
    free (b);
  }
  lock_release (&cache_lock);
}
