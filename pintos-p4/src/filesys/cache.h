#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include <list.h>
#include "threads/synch.h"
#include "devices/block.h"

struct cache_block {
  block_sector_t sector;
  uint8_t data[BLOCK_SECTOR_SIZE];
  bool dirty;
  bool clock_bit;
  struct lock block_lock;
};

/* Type of block lock. */
enum lock_type
  {
    NON_EXCLUSIVE,	/* Any number of lockers. */
    EXCLUSIVE		/* Only one locker. */
  };

#define INVALID_SECTOR ((block_sector_t) -1)
#define CACHE_CNT 64
struct cache_block cache[CACHE_CNT];
struct lock cache_lock;


void cache_init (void);
struct cache_block *lookup_block (block_sector_t sector);
struct cache_block *get_block (block_sector_t sector);
struct cache_block *cache_evict (void);
void cache_fill (struct cache_block *b, block_sector_t sector);
void cache_read (block_sector_t src, void *dst);
void cache_write (void *src, block_sector_t dst);
void cache_flush (void);
void cache_unlock(struct cache_block *b);
void cache_dirty (struct cache_block *b);

#endif /* filesys/cache.h */
