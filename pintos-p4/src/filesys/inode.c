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

#define DIRECT_CNT 123
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

UNUSED static void deallocate_inode (const struct inode *);

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
  cache_free(sector);
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
  if (remaining == 0) goto done;
  PANIC ("Could not close inode.");
      
 done:
  cache_block_unlock (b);
  free_sector (id->sectors[DIRECT_CNT]);
  free_sector(inode->sector);
  free_sector (id->sectors[DIRECT_CNT + INDIRECT_CNT]);
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

block_sector_t byte_to_sector (const struct inode *inode, off_t pos){
  ASSERT (inode != NULL);
  struct cache_block *b = get_block (inode->sector);
  struct inode_disk *id = (struct inode_disk *) b->data;

  /* Not sure if this will need to be changed for seeks past EOF. */
  ASSERT (pos < id->length);

  block_sector_t sector = pos / BLOCK_SECTOR_SIZE;
  /* In a direct block. */
  if (sector < DIRECT_CNT){
    int data_sector = id->sectors[sector];
    cache_block_unlock(b);
    return data_sector;
  }
  sector -= DIRECT_CNT;
  /* In an indirect block -- currently implemented for only having 1 */
  if (sector < PTRS_PER_SECTOR){
    struct cache_block *b2 = get_block (id->sectors[DIRECT_CNT]);
    struct indirect_block *indir = (struct indirect_block *) b2->data;
    block_sector_t data_sector = indir->sectors[sector];
    cache_block_unlock(b);
    cache_block_unlock (b2);
    return data_sector;
  }
  sector -= PTRS_PER_SECTOR;
  /* In a dbl-indirect block -- currently implemented for only having 1 */
  if (sector < PTRS_PER_SECTOR * PTRS_PER_SECTOR){
    block_sector_t next_sector = sector / PTRS_PER_SECTOR;
    struct cache_block *b2 = get_block (id->sectors[DIRECT_CNT + INDIRECT_CNT]);
    struct indirect_block *indir = (struct indirect_block *) b2->data;
    block_sector_t dbl_sector = indir->sectors[next_sector];
    cache_block_unlock (b2);
    struct cache_block *b3 = get_block (dbl_sector);
    struct indirect_block *dbl_indir = (struct indirect_block *) b3->data;
    sector -= next_sector * PTRS_PER_SECTOR;
    block_sector_t data_sector = dbl_indir->sectors[sector];
    cache_block_unlock(b);
    cache_block_unlock (b3);
    return data_sector;
  }
  PANIC ("byte-to-sector failed.");
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset){
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;

  while (size > 0){
    /* Disk sector to read, starting byte offset within sector. */
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;
    
    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length (inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;
    
    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;
    
    block_sector_t sector_idx = byte_to_sector (inode, offset);
    struct cache_block *b = get_block (sector_idx);
    memcpy (buffer + bytes_read, (uint8_t *) b->data + sector_ofs, chunk_size);
    cache_block_unlock (b);
    
    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }  
  return bytes_read;
}


static int
extend_direct(struct inode_disk *id, int current_idx, int remaining){
  int cnt = 0;
  block_sector_t sector;
  for (; current_idx < remaining  && current_idx < DIRECT_CNT;
       current_idx++, cnt++){
      free_map_allocate(&sector);
      //Set to
      struct cache_block *b = get_block (sector);
      cache_zero(b);
      cache_block_unlock (b);
      id->sectors[current_idx] = sector;
  }
  return cnt;
}

static int
extend_indirect(struct indirect_block *indir, int current_idx, int remaining){
  int cnt = 0;
  block_sector_t sector;
  int start_idx = current_idx;
  for (; current_idx < remaining + start_idx
         && current_idx < PTRS_PER_SECTOR;
       current_idx++, cnt++){
    free_map_allocate(&sector);
    /* Set to 0 */
    struct cache_block *b = get_block (sector);
    cache_zero(b);
    cache_block_unlock (b);
    indir->sectors[current_idx] = sector;
  }
  return cnt;
 
}

static int
extend_dbl(struct indirect_block *dbl_indir, int current_idx, int remaining){
  int cnt = 0;
  block_sector_t sector;
  int start_idx = current_idx;
  int dbl_idx = current_idx / PTRS_PER_SECTOR;
  for (; dbl_idx < PTRS_PER_SECTOR && current_idx < remaining + start_idx;
       current_idx++, cnt++){
    if (!dbl_indir->sectors[dbl_idx]){
      free_map_allocate (&sector);
      dbl_indir->sectors[dbl_idx] = sector;
    }
    int indir_current_idx = current_idx - dbl_idx * PTRS_PER_SECTOR;
    struct cache_block *b = get_block (dbl_indir->sectors[dbl_idx]);
    cache_dirty(b);
    struct indirect_block *indir = (struct indirect_block *) b->data;
    int amount_filled = extend_indirect (indir, indir_current_idx, remaining);
    cache_block_unlock (b);    
    //remaining -= amount_filled;
    current_idx += amount_filled;
    dbl_idx = current_idx / PTRS_PER_SECTOR;
  }
  return cnt;
}

bool
extend_file (struct inode *inode, off_t length){
  bool success = true;
  struct cache_block *id_block = NULL;
  struct cache_block *indir_block = NULL;
  struct cache_block *dbl_block = NULL;
  
  int current_length = inode_length(inode);

  size_t current_idx = bytes_to_sectors(current_length);
  size_t remaining = bytes_to_sectors(length) + 1;
  id_block = get_block(inode->sector);

  struct inode_disk *id = (struct inode_disk *)id_block->data;
  id->length = length;

  if (remaining <= current_idx)
    goto done;
  
  current_idx += extend_direct(id, current_idx, remaining);

  if (remaining <= current_idx)
    goto done;
  
  if (!id->sectors[DIRECT_CNT]){
    block_sector_t sector;
    free_map_allocate(&sector);
    id->sectors[DIRECT_CNT] = sector;    
  }

  indir_block = get_block(id->sectors[DIRECT_CNT]);  
  struct indirect_block *indir = (struct indirect_block *)indir_block->data;
  current_idx += extend_indirect(indir, current_idx - DIRECT_CNT, remaining);
  
  if (remaining <= current_idx)
    goto done;
  
  if (!id->sectors[DIRECT_CNT + INDIRECT_CNT]){
    block_sector_t sector;
    free_map_allocate(&sector);
    id->sectors[DIRECT_CNT + INDIRECT_CNT] = sector;    
  }

  dbl_block = get_block(id->sectors[DIRECT_CNT + INDIRECT_CNT]);  
  struct indirect_block *dbl_indir = (struct indirect_block *)dbl_block->data;
  current_idx += extend_dbl(dbl_indir,
			     current_idx - (DIRECT_CNT + PTRS_PER_SECTOR),
			     remaining);
  
  if (remaining > current_idx){
    success = false;
    id->length = (current_idx - 1) * BLOCK_SECTOR_SIZE;
  }

 done:
  cache_dirty(id_block);
  cache_dirty(indir_block);
  cache_dirty(dbl_block);
  cache_block_unlock (id_block);
  cache_block_unlock (indir_block);
  cache_block_unlock (dbl_block);  
  return success;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t inode_write_at (struct inode *inode, const void *buffer_, off_t size, off_t offset){
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;

  if (inode->deny_write_cnt)
    return 0;
  
  off_t current_length = inode_length (inode);
  if (offset + size > current_length){
    extend_file (inode, offset + size);
  }

  while (size > 0){
    /* Sector to write, starting byte offset within sector. */
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;
    
    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length (inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0){
      break;
    }

    block_sector_t sector_idx = byte_to_sector (inode, offset);
    struct cache_block *b = get_block (sector_idx);
    memcpy ((uint8_t *) &b->data + sector_ofs, buffer + bytes_written, chunk_size);
    cache_dirty(b);
    cache_block_unlock (b);

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }
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
