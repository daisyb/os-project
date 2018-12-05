#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include <list.h>
#include "threads/synch.h"
#include "devices/block.h"

struct list cache;
struct lock cache_lock;
struct cache_block {
  block_sector_t sector;
  uint8_t data[BLOCK_SECTOR_SIZE];
  bool dirty;
  bool clock_bit;
  struct list_elem elem;
};

void cache_init (void);
struct cache_block *lookup_block (block_sector_t sector);
struct cache_block *get_block (block_sector_t sector);
struct cache_block *cache_evict (void);
void cache_fill (struct cache_block *b, block_sector_t sector);
void cache_flush (void);

#endif	/* filesys/cache.h */
