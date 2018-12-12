#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include <stdio.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "filesys/cache.h"
#include "threads/thread.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define DIRECT_CNT 122
#define INDIRECT_CNT 1
#define DBL_INDIRECT_CNT 1
#define SECTOR_CNT (DIRECT_CNT + INDIRECT_CNT + DBL_INDIRECT_CNT)

#define PTRS_PER_SECTOR ((off_t) (BLOCK_SECTOR_SIZE / sizeof (block_sector_t)))
#define INODE_SPAN ((DIRECT_CNT \
		     + PTRS_PER_SECTOR * INDIRECT_CNT \
		     + PTRS_PER_SECTOR * PTRS_PER_SECTOR * DBL_INDIRECT_CNT) \
		     * BLOCK_SECTOR_SIZE)

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk {
  block_sector_t sectors[SECTOR_CNT]; /* Sectors */
  enum inode_type type;		/* FILE_INODE or DIR_INODE */
  off_t length;			/* File size in bytes */
  off_t read_length;		/* Readable file size in bytes */
  unsigned magic;			/* Magic number */
};

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors (off_t size){
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode {
  struct list_elem elem;              /* Element in inode list. */
  block_sector_t sector;              /* Sector number of disk location. */
  int open_cnt;                       /* Number of openers. */
  bool removed;                       /* True if deleted, false otherwise. */
  struct lock lock;			/* Protects the inode */
  
  struct lock deny_write_lock;        /* Protects members below */
  struct condition no_writers_cond;	/* Signaled when no writers */
  int deny_write_cnt;			/* 0: writes ok, >0: deny writes */
  int writer_cnt;			/* Number of writers */
};

struct indirect_block {
  block_sector_t sectors[PTRS_PER_SECTOR];
  unsigned magic;
};
  
/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Controls access to open_inodes list */
static struct lock open_inodes_lock;

/* Initializes the inode module. */
void inode_init (void){
  list_init (&open_inodes);
  lock_init (&open_inodes_lock);
}

/* Creates a new inode_disk of length 0, stored in sector SECTOR. */
struct inode *inode_create (block_sector_t sector, enum inode_type type){
  struct inode_disk *disk_inode = NULL;

  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL){
    disk_inode->type = type;
    disk_inode->length = 0;
    disk_inode->read_length = 0;
    disk_inode->magic = INODE_MAGIC;

    struct cache_block *b = get_block (sector);
    memcpy (b->data, disk_inode, BLOCK_SECTOR_SIZE);
    cache_dirty(b);
    cache_block_unlock (b);
    free (disk_inode);
    struct inode *inode = inode_open (sector);
    return inode;
  }
  return NULL;
}

struct inode *inode_open (block_sector_t sector){
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); 
       e != list_end (&open_inodes);
       e = list_next (e)){
    inode = list_entry (e, struct inode, elem);
    if (inode->sector == sector){
      inode_reopen (inode);
      return inode; 
    }
  }
  
  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->removed = false;
  lock_init (&inode->lock);
  lock_init (&inode->deny_write_lock);
  cond_init (&inode->no_writers_cond);
  inode->deny_write_cnt = 0;
  inode->writer_cnt = 0;
  return inode;
}

/* Reopens and returns INODE. */
struct inode *inode_reopen (struct inode *inode){
  if (inode != NULL){
    lock_acquire (&open_inodes_lock);
    inode->open_cnt++;
    lock_release (&open_inodes_lock);
  }
  return inode;
}

/* Returns the type of INODE. */
enum inode_type inode_get_type (const struct inode *inode){
  struct cache_block* b = get_block (inode->sector);
  struct inode_disk *id = (struct inode_disk *) b->data;
  int type = id->type;
  cache_block_unlock (b);
  return type;
}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber (const struct inode *inode){
  return inode->sector;
}

static void
free_sector(block_sector_t sector){
  if (!sector) return;
  //cache_free(sector);
  free_map_release(sector);
}

static block_sector_t
close_indirect_block (struct indirect_block *indir, block_sector_t remaining){
  block_sector_t sector = 0;
  while (remaining > 0 && sector < PTRS_PER_SECTOR){    
    free_sector(indir->sectors[sector]);
    remaining--;
    sector++;
  }
  return remaining;
}


static void
close_inode_sectors(struct inode *inode){
  struct cache_block *b = get_block (inode->sector);
  struct inode_disk *id = (struct inode_disk *) b->data;
  block_sector_t remaining = bytes_to_sectors (id->length);
      
  block_sector_t sector = 0;
  while (remaining > 0 && sector < DIRECT_CNT){
    free_sector (id->sectors[sector]);
    remaining--;
    sector++;
  }
  if (remaining == 0) goto done;
      
  struct cache_block *b2 = get_block (id->sectors[DIRECT_CNT]);
  struct indirect_block *indir = (struct indirect_block *) b2->data;
  remaining = close_indirect_block (indir, remaining);
  cache_block_unlock (b2);
  free_sector (id->sectors[DIRECT_CNT]);
  if (remaining == 0) goto done;

  sector = 0;
  b2 = get_block (id->sectors[DIRECT_CNT + INDIRECT_CNT]);
  struct indirect_block *dbl_indir = (struct indirect_block *) b2->data;
  struct cache_block *b3;
  while (remaining > 0 && sector < PTRS_PER_SECTOR){
    b3 = get_block (dbl_indir->sectors[sector]);
    indir = (struct indirect_block *) b3->data;
    remaining = close_indirect_block (indir, remaining);
    free_sector (dbl_indir->sectors[sector]);
    cache_block_unlock (b3);
    sector++;
  }
  free_sector (id->sectors[DIRECT_CNT + INDIRECT_CNT]);
  if (remaining == 0) goto done;
  PANIC ("Could not close inode.");
      
 done:
  cache_block_unlock (b);
  free_sector(inode->sector);
}


/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close (struct inode *inode){
  if (inode == NULL)
    return;
  lock_acquire (&open_inodes_lock);
  int open_cnt = --inode->open_cnt;
  lock_release (&open_inodes_lock);
  if (open_cnt == 0){
    list_remove (&inode->elem);
    if (inode->removed){
      close_inode_sectors(inode);
    }    
    free (inode); 
  }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove (struct inode *inode){
  ASSERT (inode != NULL);
  inode->removed = true;
}


/* Translates SECTOR_IDX into a sequence of block indexes in
   OFFSETS and sets *OFFSET_CNT to the number of offsets. */
static void
calculate_indices (off_t sector_idx, size_t offsets[], size_t *offset_cnt)
{
  /* Handle direct blocks. */
  if (sector_idx < DIRECT_CNT){
    *offset_cnt = 1;
    offsets[0] = sector_idx;
    return;
  }

  /* Handle indirect blocks. */
  if (sector_idx < DIRECT_CNT + PTRS_PER_SECTOR){
    *offset_cnt = 2;
    /* Indirect block */
    offsets[0] = DIRECT_CNT;
    /* Index into indirect blk */
    offsets[1] = sector_idx - DIRECT_CNT;
    return;
  }

  /* Handle doubly indirect blocks. */
  *offset_cnt = 3;
  /* Dbl indirect block */
  offsets[0] = DIRECT_CNT + INDIRECT_CNT;
  /* Indirect block */
  sector_idx -= DIRECT_CNT;
  offsets[1] = sector_idx / PTRS_PER_SECTOR;
  /* Index into indirect blk */
  sector_idx -= offsets[1] * PTRS_PER_SECTOR;
  offsets[2] = sector_idx;
}

/* Retrieves the data block for the given byte OFFSET in INODE,
   setting *DATA_BLOCK to the block.
   Returns true if successful, false on failure.
   If ALLOCATE is false, then missing blocks will be successful
   with *DATA_BLOCk set to a null pointer.
   If ALLOCATE is true, then missing blocks will be allocated.
   The block returned will be locked, normally non-exclusively,
   but a newly allocated block will have an exclusive lock. */
static bool
get_data_block (struct inode *inode, off_t offset, bool allocate,
                struct cache_block **data_block)
{

  size_t off_cnt;
  size_t offsets[3];
  calculate_indices(offset / BLOCK_SECTOR_SIZE, offsets, &off_cnt);

  struct cache_block *b; 
  struct indirect_block *indir;
  block_sector_t next_sector = inode->sector;
  size_t i;
  for(i = 0; i < off_cnt; i++){
    /* Get indirect or inode block */
    b = get_block(next_sector);
    indir = (struct indirect_block *)b->data;
    block_sector_t sector_idx = offsets[i];
    if (!indir->sectors[sector_idx]){
      /* Allocate another sector */
      if (allocate){
        if (!free_map_allocate(&indir->sectors[sector_idx])){
          cache_block_unlock(b);
          return false;
        }
        cache_dirty(b);
      } else{
        cache_block_unlock(b);
        *data_block = NULL;
        return true;
      }
    }
    next_sector = indir->sectors[sector_idx];
    cache_block_unlock(b);
  }

  *data_block = get_block(next_sector);
  return true;
}


/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset)
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;

  while (size > 0){
    /* Sector to read, starting byte offset within sector, sector data. */
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;
    struct cache_block *block;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length (inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0 || !get_data_block (inode, offset, false, &block))
      break;

    if (block == NULL)
      memset (buffer + bytes_read, 0, chunk_size);
    else
      {
        const uint8_t *sector_data = block->data;
        memcpy (buffer + bytes_read, sector_data + sector_ofs, chunk_size);
        cache_block_unlock (block);
      }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }

  return bytes_read;
}

void
extend_file (struct inode *inode, off_t length){
  struct cache_block *b = get_block(inode->sector);
  struct inode_disk *id = (struct inode_disk *)b->data;
  if (id->length < length){
    id->read_length = id->length;
    id->length = length;
    cache_dirty(b);
  }
  cache_block_unlock(b);
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size, off_t offset){
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;

  lock_acquire (&inode->deny_write_lock);
  if (inode->deny_write_cnt){
    lock_release (&inode->deny_write_lock);
    return 0;
  }
  inode->writer_cnt++;
  lock_release (&inode->deny_write_lock);

  while (size > 0)
    {
      /* Sector to write, starting byte offset within sector, sector data. */
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;
      struct cache_block *block;
      uint8_t *sector_data;

      /* Bytes to max inode size, bytes left in sector, lesser of the two. */
      off_t inode_left = INODE_SPAN - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;

      if (chunk_size <= 0 || !get_data_block (inode, offset, true, &block))
        break;

      sector_data = block->data;
      memcpy (sector_data + sector_ofs, buffer + bytes_written, chunk_size);
      cache_dirty (block);
      cache_block_unlock (block);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }

  extend_file (inode, offset);

  lock_acquire (&inode->deny_write_lock);
  if (--inode->writer_cnt == 0)
    cond_signal (&inode->no_writers_cond, &inode->deny_write_lock);
  lock_release (&inode->deny_write_lock);
  
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write (struct inode *inode){
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write (struct inode *inode){
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length (const struct inode *inode){
  struct cache_block *b = get_block (inode->sector);
  struct inode_disk *id = (struct inode_disk *) b->data;
  int length = id->length;
  cache_block_unlock (b);
  return length;
}

/* Returns the number of openers. */
int inode_open_cnt (const struct inode *inode){
  int open_cnt;

  lock_acquire (&open_inodes_lock);
  open_cnt = inode->open_cnt;
  lock_release (&open_inodes_lock);

  return open_cnt;
}

/* Locks INODE. */
void inode_lock (struct inode *inode){
  lock_acquire (&inode->lock);
}

/* Releases INODE's lock. */
void inode_unlock (struct inode *inode){
  lock_release (&inode->lock);
}
