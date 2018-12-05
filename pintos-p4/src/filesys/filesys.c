#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/directory.h"
#include "threads/thread.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();

  if (format) 
    do_format ();
  free_map_open ();
  thread_current()->working_dir = dir_open_root();
}

/* Extracts a file name part from *SRCP into PART,
   and updates *SRCP so that the next call will return the next
   file name part.
   Returns 1 if successful, 0 at end of string, -1 for a too-long
   file name part. */
static int
get_next_part (char part[NAME_MAX], const char **srcp)
{
  const char *src = *srcp;
  char *dst = part;

  /* Skip leading slashes.
     If it's all slashes, we're done. */
  while (*src == '/')
    src++;
  if (*src == '\0')
    return 0;

  /* Copy up to NAME_MAX character from SRC to DST.
     Add null terminator. */
  while (*src != '/' && *src != '\0')
    {
      if (dst < part + NAME_MAX)
        *dst++ = *src;
      else
        return -1;
      src++;
    }
  *dst = '\0';

  /* Advance source pointer. */
  *srcp = src;
  return 1;
}

/* Resolves relative or absolute file NAME.
   Returns true if successful, false on failure.
   Stores the directory corresponding to the name into *DIRP,
   and the file name part into BASE_NAME. */
static bool
resolve_name_to_entry (const char *name,
                       struct dir **dirp, char base_name[NAME_MAX + 1])
{

  struct thread *t = thread_current();
  *dirp = *name == '/'? dir_open_root() : t->working_dir;
  if (!strcmp(name, "")) return false;
  const char **namep = &name;
  struct inode *inode = NULL;
  int value;
  while((value = get_next_part(base_name, namep)) && **namep != '\0'){
    if (value == -1) return false;
    if (!dir_lookup(*dirp, base_name, &inode) 
        || inode_get_type(inode) == FILE_INODE){ 
      return false;
    }
    if (inode != NULL){
      if (*dirp != t->working_dir)
        dir_close(*dirp);
      *dirp = dir_open(inode);
    }
  }
  return true;
}

/* Resolves relative or absolute file NAME to an inode.
   Returns an inode if successful, or a null pointer on failure.
   The caller is responsible for closing the returned inode. */
static struct inode *
resolve_name_to_inode (const char *name)
{
  struct inode *inode = NULL;
  struct dir *dirp;
  char base_name[NAME_MAX + 1] = ".";
  if (resolve_name_to_entry(name, &dirp, base_name)){
    dir_lookup(dirp, base_name, &inode);
  }
  return inode;
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size, enum inode_type type) 
{
  block_sector_t inode_sector = 0;
  struct dir *dir;
  char base_name[NAME_MAX + 1];
  bool success = (resolve_name_to_entry(name, &dir, base_name) 
                  && dir
                  && free_map_allocate(1, &inode_sector));
  if (type == DIR_INODE)
    success = success && dir_create(inode_sector, dir_get_inumber(dir));
  else {
    success = success && inode_create(inode_sector, initial_size, type);
  }  
  success = success && dir_add(dir, base_name, inode_sector);

  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  
  if (dir != thread_current()->working_dir)
    dir_close (dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the inode if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct inode *
filesys_open (const char *name)
{
  return resolve_name_to_inode(name);
}

/* Change current directory to NAME.
   Return true if successful, false on failure. */
bool
filesys_chdir (const char *name)
{
  struct thread *t = thread_current();
  struct inode *inode = resolve_name_to_inode(name);
  if (!inode) return false;
  dir_close(t->working_dir);
  t->working_dir = dir_open(inode);
  return true;
}


/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  struct dir *dir;
  char base_name[NAME_MAX + 1];

  bool success = (resolve_name_to_entry(name, &dir, base_name) 
                  && dir != NULL 
                  && dir_remove (dir, base_name));
  dir_close (dir); 
  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, ROOT_DIR_SECTOR))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}
