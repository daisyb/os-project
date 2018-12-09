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
#define INODE_SPAN ((DIRECT_CNT
		     + PTRS_PER_SECTOR * INDIRECT_CNT
		     + PTRS_PER_SECTOR * PTRS_PER_SECTOR * DBL_INDIRECT_CNT)
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

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Controls access to open_inodes list */
static struct lock open_inodes_lock;

static void deallocate_inode (const struct inode *);

/* Initializes the inode module. */
void inode_init (void){
  list_init (&open_inodes);
  lock_init (&open_inodes_lock);
}

/* Creates a new inode_disk of length 0, stored in sector SECTOR. */
bool inode_create (block_sector_t sector, enum inode_type type){
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL){
    disk_inode->type = type;
    disk_inode->length = 0;
    disk_inode->magic = INODE_MAGIC;

    struct cache_block *b = get_block (sector);
    memcpy (b->data, disk_inode, BLOCK_SECTOR_SIZE);
    cache_block_unlock (b);
    free (disk_inode);
    success = true;
  }
  return success;
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
  cache_block_unlock (b);
  struct inode_disk *id = (struct inode_disk *) b->data;
  return id->type;
}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber (const struct inode *inode){
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close (struct inode *inode){
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  lock_acquire (&open_inodes_lock);
  int open_cnt = --inode->open_cnt;
  lock_release (&open_inodes_lock);
  if (open_cnt == 0){
    /* Remove from inode list and release lock. */
    list_remove (&inode->elem);
    
    /* Deallocate blocks if removed. */
    if (inode->removed){
      free_map_release (inode->sector, 1);
      free_map_release (inode->data.start,
			bytes_to_sectors (inode->data.length)); 
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

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset){
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  
  while (size > 0){
    /* Disk sector to read, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector (inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;
    
    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length (inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;
    
    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;
    
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
  while (size > 0){
    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector (inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;
    
    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length (inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)

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
  cache_block_unlock (b);
  struct inode_disk *id = (struct inode_disk *) b->data;
  return id->length;
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
