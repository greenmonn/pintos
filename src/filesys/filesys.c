#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/cache.h"
#include "devices/disk.h"

/* The disk that contains the file system. */
struct disk *filesys_disk;
struct lock disk_lock;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  filesys_disk = disk_get (0, 1);
  if (filesys_disk == NULL)
    PANIC ("hd0:1 (hdb) not present, file system initialization failed");

  lock_init(&disk_lock);
  inode_init ();
  free_map_init ();
  cache_init ();

  if (format) 
    do_format ();

  free_map_open ();

}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
    /* write back cache */
    lock_acquire(&cache_lock);
    struct hash_iterator i;
    hash_first (&i, &buffer_cache);
    while (hash_next(&i))
    {
        struct cache_entry *ce = hash_entry (hash_cur(&i), struct cache_entry, elem);
        if (ce->dirty == true) {
            disk_write(filesys_disk, ce->sector_no, ce->data);
        }
    }
    lock_release(&cache_lock);


    free_map_close ();

}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size, struct dir *file_dir) 
{
  disk_sector_t inode_sector = 0;
  struct dir *dir;
  if (file_dir == NULL) {
    dir = dir_open_root ();
  } else {
      dir = dir_reopen(file_dir);
  }

  bool free_map_success, inode_create_success, dir_add_success;
  bool success = (dir != NULL
                  && (free_map_success = free_map_allocate (1, &inode_sector))
                  && (inode_create_success = inode_create (inode_sector, initial_size, false))
                  && (dir_add_success = dir_add (dir, name, inode_sector)));
  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  dir_close (dir);
  //printf("%d %d %d\n", free_map_success, inode_create_success, dir_add_success);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  struct dir *dir;
  if (thread_current()->current_dir){
  	dir = dir_reopen(thread_current()->current_dir);
  } else {
	dir = dir_open_root();
  }
  struct inode *inode = NULL;

  if (dir != NULL)
    dir_lookup (dir, name, &inode);
  dir_close (dir);

  return file_open (inode);
}

struct file *
filesys_open_dir (const char *name, struct dir *t_dir)
{
  struct dir *dir = t_dir;
  struct inode *inode = NULL;

  if (dir != NULL)
    dir_lookup (dir, name, &inode);
  dir_close (dir);

  return file_open (inode);
}



/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name, struct dir *file_dir) 
{
  struct dir *dir;
  if (file_dir == NULL)
      dir = dir_open_root ();
  else {
      dir = dir_reopen(file_dir);
  }
  bool success = dir != NULL && dir_remove (dir, name);
  dir_close (dir); 

  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  struct dir *root_dir = dir_open_root();
  root_dir->inode->data.parent = ROOT_DIR_SECTOR;
  struct inode_disk *temp_disk = malloc(sizeof (struct inode_disk));
  inode_data_to_disk(temp_disk, &root_dir->inode->data);
  //disk_write(filesys_disk, ROOT_DIR_SECTOR, 
  disk_write(filesys_disk, ROOT_DIR_SECTOR, temp_disk);
  free(temp_disk);
  //dir_add_relative(root_dir, ".", ROOT_DIR_SECTOR);
  //dir_add_relative(root_dir, "..", ROOT_DIR_SECTOR);
  free_map_close ();
  printf ("done.\n");
}
