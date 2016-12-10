#include "filesys/inode.h"
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "filesys/cache.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define DIRECT_INDEX_SIZE 9
#define INDIRECT_INDEX_SIZE 4

#define DIRECT_INDEX_RANGE 9
#define INDIRECT_INDEX_RANGE (9 + 128 * 4)


/* On-disk inode.
   Must be exactly DISK_SECTOR_SIZE bytes long. */
//struct inode_disk
//  {
//    off_t length;                       /* File size in bytes. */
//    unsigned magic;                     /* Magic number. */
//    uint32_t unused[111];               /* Not used. */
//    bool unused_bool[3];
//	disk_sector_t direct_idx[9];
//    disk_sector_t indirect_idx[4];
//    disk_sector_t double_indirect_idx;
//	bool is_dir;
//  };
//

void inode_data_to_disk(struct inode_disk *dst, struct inode_data *src) {
    memset(dst, 0, sizeof (struct inode_disk));
    dst->length = src->length;
    dst->magic = src->magic;
    int i;
    for (i=0; i<9; i++) {
        dst->direct_idx[i] = src->direct_idx[i];

    }
    for (i=0; i<4; i++) {
        dst->indirect_idx[i] = src->indirect_idx[i];
    }
    dst->double_indirect_idx = src->double_indirect_idx;
    dst->is_dir = src->is_dir;
    dst->parent = src->parent;

    //memcpy(dst, src, sizeof (struct inode_data));
}

void inode_disk_to_data(struct inode_data *dst, struct inode_disk *src) {
    dst->length = src->length;
    dst->magic = src->magic;
    int i;
    for (i=0; i<9; i++) {
        dst->direct_idx[i] = src->direct_idx[i];

    }
    for (i=0; i<4; i++) {
        dst->indirect_idx[i] = src->indirect_idx[i];
    }
    dst->double_indirect_idx = src->double_indirect_idx;
    dst->is_dir = src->is_dir;
    dst->parent = src->parent;

    //memcpy(dst, src, sizeof (struct inode_data));
}


struct indirect_block
{
    disk_sector_t entry[128];
};

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, DISK_SECTOR_SIZE);
}

/* In-memory inode. */
//struct inode 
//  {
//    struct list_elem elem;              /* Element in inode list. */
//    disk_sector_t sector;               /* Sector number of disk location. */
//    int open_cnt;                       /* Numer of openers. */
//    bool removed;                       /* True if deleted, false otherwise. */
//    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
//    struct inode_disk data;             /* Inode content. */
//	bool is_dir;
//  };

/* Returns the disk sector that contains byte offset POS within
   INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static disk_sector_t
byte_to_sector (off_t pos) 
{
    return (pos / DISK_SECTOR_SIZE);
}

disk_sector_t
byte_to_sector_indexed (struct inode *inode, off_t pos, int length)
{
    ASSERT(inode != NULL);
    if (pos < ROUND_UP(length, DISK_SECTOR_SIZE)) {
        disk_sector_t sector_pos = byte_to_sector(pos);

        if (sector_pos < DIRECT_INDEX_RANGE) {
            return inode->data.direct_idx[sector_pos];
        }
        else if (sector_pos < INDIRECT_INDEX_RANGE) {
            int indirect_index = (sector_pos - DIRECT_INDEX_SIZE) / 128;
            int block_entry = (sector_pos - DIRECT_INDEX_SIZE) % 128;
            struct indirect_block accessed_block;

            disk_read(filesys_disk, inode->data.indirect_idx[indirect_index], &accessed_block);
            return accessed_block.entry[block_entry];
        }
        else {
            int first_block_entry = (sector_pos - INDIRECT_INDEX_RANGE) / 128;
            int second_block_entry = (sector_pos - INDIRECT_INDEX_RANGE) % 128;
            struct indirect_block accessed_first_block;
            struct indirect_block accessed_second_block;
            disk_read(filesys_disk, inode->data.double_indirect_idx, &accessed_first_block);
            disk_read(filesys_disk, accessed_first_block.entry[first_block_entry], &accessed_second_block);
            return accessed_second_block.entry[second_block_entry];
        }

    }
    else
        return -1;
}

bool alloc_sectors(struct inode_disk *disk_inode, disk_sector_t sector, size_t sectors) {
    bool success = false;
    size_t i, j;
    static char zeros[DISK_SECTOR_SIZE];

    /* CASE 1 */
    if (sectors <= DIRECT_INDEX_RANGE) {
        for (i = 0 ; i < sectors ; i++) {
            free_map_allocate(1, &disk_inode->direct_idx[i]);
            disk_write(filesys_disk, disk_inode->direct_idx[i], zeros);
        }

        disk_write(filesys_disk, sector, disk_inode);

        success = true;
    }

    /* CASE 2 */
    else if (sectors <= INDIRECT_INDEX_RANGE) {
          for (i = 0 ; i < DIRECT_INDEX_SIZE ; i++ ) {
              free_map_allocate(1, &disk_inode->direct_idx[i]);
              disk_write(filesys_disk, disk_inode->direct_idx[i], zeros);
              /* FILLED ZERO IN ACTUAL DATA SECTOR */
          }

          size_t last_indirect_index = (sectors - DIRECT_INDEX_SIZE) / 128;
          size_t last_indirect_block_index = (sectors - DIRECT_INDEX_SIZE) % 128;
          struct indirect_block single;
          for (i = 0 ; i < last_indirect_index ; i++) {
              free_map_allocate(1, &disk_inode->indirect_idx[i]);
              //Fill the indirect block's entry
              for (j = 0 ; j < 128 ; j++) {
                  free_map_allocate(1, &single.entry[j]);
                  disk_write(filesys_disk, single.entry[j], zeros);
                  //printf("%d block entry : %d sector\n", j, single.entry[j]);
                  /* FILLED ZERO IN ACTUAL DATA SECTOR */
              }
              disk_write(filesys_disk, disk_inode->indirect_idx[i], &single);
          }
   
          /* Last indirect block - partially filled */
          if (last_indirect_block_index != 0) {
              free_map_allocate(1, &disk_inode->indirect_idx[last_indirect_index]);
              for (i = 0; i < last_indirect_block_index; i++) {
                  free_map_allocate(1, &single.entry[i]);
                  disk_write(filesys_disk, single.entry[i], zeros);
                  /* FILLED ZERO IN ACTUAL DATA SECTOR */

              }
              disk_write(filesys_disk, disk_inode->indirect_idx[last_indirect_index], &single);
              disk_write(filesys_disk, sector, disk_inode);

              success = true;
          }
          else {
              disk_write(filesys_disk, sector, disk_inode);
              success = true;
          }
      }

      /* CASE 3 */
      else {
          //Doubly-indirect block
          //1. Fill all of the previous index first!
          for (i = 0 ; i <= DIRECT_INDEX_SIZE ; i++ ) {
              free_map_allocate(1, &disk_inode->direct_idx[i]);
              disk_write(filesys_disk, disk_inode->direct_idx[i], zeros);
              /* FILLED ZERO IN ACTUAL DATA SECTOR */
          }

          struct indirect_block single;
          struct indirect_block doubly;
          for (i = 0 ; i <= INDIRECT_INDEX_SIZE ; i++) {
              free_map_allocate(1, &disk_inode->indirect_idx[i]);
              //Fill the indirect block's entry
              for (j = 0 ; j < 128 ; j++) {
                  free_map_allocate(1, &single.entry[j]);
                  disk_write(filesys_disk, single.entry[j], zeros);
                  /* FILLED ZERO IN ACTUAL DATA SECTOR */
              }
              disk_write(filesys_disk, disk_inode->indirect_idx[i], &single);
          }

          //2. Fill the 2-level index blocks
          size_t first_level_index = (sectors - INDIRECT_INDEX_RANGE) / 128;
          size_t second_level_index = (sectors - INDIRECT_INDEX_RANGE) % 128;
          free_map_allocate(1, &disk_inode->double_indirect_idx);

          for (i = 0 ; i < first_level_index ; i++) {
              free_map_allocate(1, &single.entry[i]);
              for (j = 0 ; j < 128 ; j++) {
                  free_map_allocate(1, &doubly.entry[j]);
                  disk_write(filesys_disk, doubly.entry[j], zeros);
                  /* FILLED ZERO IN ACTUAL DATA SECTOR */
              }
              disk_write(filesys_disk, single.entry[i], &doubly);
          }
          /* Fill the last partial one */
          if (second_level_index != 0) {
              free_map_allocate(1, &single.entry[first_level_index]);
              for (j = 0; j < second_level_index; j++) {
                  free_map_allocate(1, &doubly.entry[j]);
                  disk_write(filesys_disk, doubly.entry[j], zeros);
                  /* FILLED ZERO IN ACTUAL DATA SECTOR */
              }
              disk_write(filesys_disk, single.entry[first_level_index], &doubly);
              /* ALL INDEX ALLOCATED */
              disk_write(filesys_disk, disk_inode->double_indirect_idx, &single);
              disk_write(filesys_disk, sector, disk_inode);

              success = true;
          }
          else {
              disk_write(filesys_disk, disk_inode->double_indirect_idx, &single);
        disk_write(filesys_disk, sector, disk_inode);
              success = true;
          }
      } //end of 'else'
      return success;
}

bool alloc_sectors_grow(struct inode *inode, disk_sector_t sector, size_t sectors, size_t newlength) {
    bool success = false;
    struct inode_data *disk_inode = &inode->data;
    size_t i, j;
    static char zeros[DISK_SECTOR_SIZE];

    size_t pos = byte_to_sector(disk_inode->length);
    //inode->data.length = newlength;

    //printf("current %dst sector -> grow to %d sectors\n", pos, sectors);
       
    /* CASE 1 */
    if (sectors <= DIRECT_INDEX_RANGE) {
        for (i = pos ; i < sectors ; i++) {
            free_map_allocate(1, &disk_inode->direct_idx[i]);
            //printf("alloc direct_idx[%d] = %d\n", i, disk_inode->direct_idx[i]);
            disk_write(filesys_disk, disk_inode->direct_idx[i], zeros);
        }
        struct inode_disk *temp_sector = malloc(sizeof (struct inode_disk));
        inode_data_to_disk(temp_sector, disk_inode);
        disk_write(filesys_disk, sector, temp_sector);
        free(temp_sector);
        success = true;
    }

    /* CASE 2 */
    else if (sectors <= INDIRECT_INDEX_RANGE) {
        if (pos < DIRECT_INDEX_SIZE) {
          for (i = pos; i < DIRECT_INDEX_SIZE ; i++ ) {
              free_map_allocate(1, &disk_inode->direct_idx[i]);
              //printf("alloc direct_idx[%d], sector %d\n", i, disk_inode->direct_idx[i]);
              disk_write(filesys_disk, disk_inode->direct_idx[i], zeros);
              /* FILLED ZERO IN ACTUAL DATA SECTOR */
          }
        }

        size_t curr_indirect_index = (pos - DIRECT_INDEX_SIZE) / 128;
        size_t curr_block_entry = (pos - DIRECT_INDEX_SIZE) % 128;
        if (pos < DIRECT_INDEX_SIZE) {
            curr_indirect_index = 0;
            curr_block_entry = 0;
        }


          size_t last_indirect_index = (sectors - DIRECT_INDEX_SIZE) / 128;
          size_t last_indirect_block_index = (sectors - DIRECT_INDEX_SIZE) % 128;
          struct indirect_block single;
          for (i = curr_indirect_index ; i < last_indirect_index ; i++) {
              if (i != curr_indirect_index) {
                  /* New index block */
                  free_map_allocate(1, &disk_inode->indirect_idx[i]);
                  //printf("Create single indirect index block[%d] : %d\n", i, disk_inode->indirect_idx[i]);
              }               
              //Fill the indirect block's entry
              if (i == curr_indirect_index) {
                  j = curr_block_entry;
                  if (curr_block_entry == 0) {
                      /* New index block */
                      free_map_allocate(1, &disk_inode->indirect_idx[i]);
                  }
                  else {
                      /* partially filled index block is already exist */
                      disk_read(filesys_disk, disk_inode->indirect_idx[i], &single); 
                  }
              } else {
                  j = 0;
              }

              for ( ; j < 128 ; j++) {
                  free_map_allocate(1, &single.entry[j]);
                  disk_write(filesys_disk, single.entry[j], zeros);
                  //printf("%d block entry : %d sector\n", j, single.entry[j]);
                  /* FILLED ZERO IN ACTUAL DATA SECTOR */
              }
              disk_write(filesys_disk, disk_inode->indirect_idx[i], &single);
          }

          /* Last indirect block - partially filled */
          if (last_indirect_block_index != 0) {
              if (last_indirect_index == curr_indirect_index) {
                  /* Should handle case : start position is not 'first of the index block' - index block is already allocated! */
                  i = curr_block_entry;
                  if (curr_block_entry == 0) {
                      free_map_allocate(1, &disk_inode->indirect_idx[last_indirect_index]);

                      //printf("Create single indirect index block[%d] : %d\n", i, disk_inode->indirect_idx[i]);
                  }
                  else {
                      /* partially filled index block is already exist */
                      disk_read(filesys_disk, disk_inode->indirect_idx[curr_indirect_index], &single); 
                      //printf("read from existing index block %d\n", disk_inode->indirect_idx[i]);
                  }
              } else {
                  free_map_allocate(1, &disk_inode->indirect_idx[last_indirect_index]);
                  //printf("Create single indirect index block[%d] : %d\n", i, disk_inode->indirect_idx[i]);
                  i = 0;
              }
              for ( ; i < last_indirect_block_index; i++) {
                  free_map_allocate(1, &single.entry[i]);
                  //printf("alloc single.entry[%d] : %d\n", i, single.entry[i]);
                  disk_write(filesys_disk, single.entry[i], zeros);
                  /* FILLED ZERO IN ACTUAL DATA SECTOR */
              }
              disk_write(filesys_disk, disk_inode->indirect_idx[last_indirect_index], &single);
              struct inode_disk *temp_sector = malloc(sizeof (struct inode_disk));
              inode_data_to_disk(temp_sector, disk_inode);
              disk_write(filesys_disk, sector, temp_sector);
              free(temp_sector);
              success = true;
          }
          else {
              struct inode_disk *temp_sector = malloc(sizeof (struct inode_disk));
              inode_data_to_disk(temp_sector, disk_inode);
              disk_write(filesys_disk, sector, temp_sector);
              free(temp_sector);
              success = true;
          }
    }

    /* CASE 3 */
    else {
        //Doubly-indirect block
        //1. Fill all of the previous index first!
        if (pos < DIRECT_INDEX_SIZE) {
            for (i = pos ; i < DIRECT_INDEX_SIZE ; i++ ) {
                  free_map_allocate(1, &disk_inode->direct_idx[i]);
                  disk_write(filesys_disk, disk_inode->direct_idx[i], zeros);
                  /* FILLED ZERO IN ACTUAL DATA SECTOR */
              }
          }

          struct indirect_block single;
          struct indirect_block doubly;

          if (pos < INDIRECT_INDEX_RANGE) {
              int curr_indirect_index = (pos - DIRECT_INDEX_SIZE) / 128;
              int curr_block_entry = (pos - DIRECT_INDEX_SIZE) % 128;

              if (pos < DIRECT_INDEX_SIZE) {
                  curr_indirect_index = 0;
                  curr_block_entry = 0;
              }

              for (i = curr_indirect_index ; i < INDIRECT_INDEX_SIZE ; i++) {
                  //Fill the single indirect block's entry
                  if (i == curr_indirect_index) {
                      j = curr_block_entry;
                      if (curr_block_entry == 0) {
                          free_map_allocate(1, &disk_inode->indirect_idx[i]);
                      } else {
                          /* partially filled index block is already exist */
                          disk_read(filesys_disk, disk_inode->indirect_idx[i], &single);
                      }
                  } else {

                      free_map_allocate(1, &disk_inode->indirect_idx[i]);
                      j = 0;
                  }
                  for ( ; j < 128 ; j++) {
                      free_map_allocate(1, &single.entry[j]);
                      disk_write(filesys_disk, single.entry[j], zeros);
                      /* FILLED ZERO IN ACTUAL DATA SECTOR */
                  }
                  disk_write(filesys_disk, disk_inode->indirect_idx[i], &single);
              }
          }

          //2. Fill the 2-level index blocks
          size_t curr_first_idx = (pos - INDIRECT_INDEX_RANGE) / 128;
          size_t curr_second_idx = (pos - INDIRECT_INDEX_RANGE) % 128;

          if (pos < INDIRECT_INDEX_RANGE) {
              curr_first_idx = 0;
              curr_second_idx = 0;
          }

          size_t first_level_index = (sectors - INDIRECT_INDEX_RANGE) / 128;
          size_t second_level_index = (sectors - INDIRECT_INDEX_RANGE) % 128;
          if(curr_first_idx == 0 && curr_second_idx == 0) {
            free_map_allocate(1, &disk_inode->double_indirect_idx);
          } else {
              disk_read(filesys_disk, disk_inode->double_indirect_idx, &single);
          }

          for (i = curr_first_idx ; i < first_level_index ; i++) {

              if (i == curr_first_idx) {
                  j = curr_second_idx;
                  if (curr_second_idx == 0) {

                      free_map_allocate(1, &single.entry[i]);
                  } else {
                      disk_read(filesys_disk, single.entry[i], &doubly);
                  }
              }
              else {
                  free_map_allocate(1, &single.entry[i]);
                  j = 0;
              }
              for ( ; j < 128 ; j++) {
                  free_map_allocate(1, &doubly.entry[j]);
                  disk_write(filesys_disk, doubly.entry[j], zeros);
                  /* FILLED ZERO IN ACTUAL DATA SECTOR */
              }
              disk_write(filesys_disk, single.entry[i], &doubly);
          }
          /* Fill the last partial one */
          if (second_level_index != 0) {
              free_map_allocate(1, &single.entry[first_level_index]);
              if (first_level_index == curr_first_idx) {
                  j = curr_second_idx;
                  if (j == 0) {
                      free_map_allocate(1, &single.entry[first_level_index]);
                  } else {
                      disk_read(filesys_disk, single.entry[first_level_index], &doubly);
                  }
              } else {
                  free_map_allocate(1, &single.entry[first_level_index]);
                  j = 0;
              } 
              for ( ; j < second_level_index; j++) {
                  free_map_allocate(1, &doubly.entry[j]);
                  disk_write(filesys_disk, doubly.entry[j], zeros);
                  /* FILLED ZERO IN ACTUAL DATA SECTOR */
              }
              disk_write(filesys_disk, single.entry[first_level_index], &doubly);
              /* ALL INDEX ALLOCATED */
              disk_write(filesys_disk, disk_inode->double_indirect_idx, &single);
              struct inode_disk *temp_sector = malloc(sizeof (struct inode_disk));
              inode_data_to_disk(temp_sector, disk_inode);
              disk_write(filesys_disk, sector, temp_sector);
              free(temp_sector);
              success = true;
          }
          else {
              disk_write(filesys_disk, disk_inode->double_indirect_idx, &single);
              struct inode_disk *temp_sector = malloc(sizeof (struct inode_disk));
              inode_data_to_disk(temp_sector, disk_inode);
              disk_write(filesys_disk, sector, temp_sector);
              free(temp_sector);
              success = true;
          }
    } //end of 'else'
    return success;
}
/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   disk.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (disk_sector_t sector, off_t length, bool is_dir)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == DISK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      size_t sectors = bytes_to_sectors (length);
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
	  disk_inode->is_dir = is_dir;
      success = alloc_sectors(disk_inode, sector, sectors);

      free (disk_inode);
    } //disk_inode != NULL
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (disk_sector_t sector) 
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL) {
      //printf("memory allocation failed\n");
    return NULL;
  }

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  //inode->writing_cnt = 0;
  inode->removed = false;
  struct inode_disk *temp_disk = malloc(sizeof(struct inode_disk));
  //printf("copy\n");
  disk_read (filesys_disk, inode->sector, temp_disk);
  inode_disk_to_data(&inode->data, temp_disk);
  free(temp_disk);
  //printf("copy end\n");
  //printf("inode_open\n");
  //printf("data copied well? %d\n", inode->data.length);
  
  lock_init(&inode->lock);
  //sema_init(&inode->sema, 0);
  return inode;

}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
disk_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
    //if (inode->removed)
    //     printf("inode_close : open_cnt %d\n", inode->open_cnt);
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
     if (inode->removed) 
        {
            //printf("Deallocate!\n");
            struct inode_data *disk_inode = &inode->data;
            int length = inode->data.length;
            int sectors = bytes_to_sectors (length);
            int i, j;
           /* CASE 1 */
            if (sectors <= DIRECT_INDEX_RANGE) {
                for (i = 0; i < sectors ; i++) {
                    free_map_release(disk_inode->direct_idx[i], 1);
                }
            }
           /* CASE 2 */
            else if (sectors <= INDIRECT_INDEX_RANGE) {
                for (i = 0 ; i < DIRECT_INDEX_SIZE ; i++ ) {
                    free_map_release(disk_inode->direct_idx[i], 1);
                }
                int last_indirect_index = (sectors - DIRECT_INDEX_SIZE) / 128;
                int last_indirect_block_index = (sectors - DIRECT_INDEX_SIZE) % 128;
                struct indirect_block single;
                
                for (i = 0; i < last_indirect_index ; i++) {
                    disk_read(filesys_disk, disk_inode->indirect_idx[i], &single);
                    for (j = 0; j<128; j++) {
                        free_map_release(single.entry[j], 1);
                    }
                    free_map_release(disk_inode->indirect_idx[i], 1);
                }
                if (last_indirect_block_index != 0) {
                    disk_read(filesys_disk, disk_inode->indirect_idx[last_indirect_index], &single);
                    for (i=0; i< last_indirect_block_index ; i++) {
                        free_map_release(single.entry[i], 1);
                    }
                    free_map_release(disk_inode->indirect_idx[last_indirect_index], 1);
                }

            }

            /* CASE 3 */
            else {
                for (i = 0 ; i < DIRECT_INDEX_SIZE ; i++) {
                    free_map_release(disk_inode->direct_idx[i], 1);
                }

                struct indirect_block single;
                struct indirect_block doubly;
                for (i = 0; i < INDIRECT_INDEX_SIZE ; i++) {
                    disk_read(filesys_disk, disk_inode->indirect_idx[i], &single);
                    for (j = 0; j < 128; j++) {
                        free_map_release(single.entry[j], 1);
                    }
                    free_map_release(disk_inode->indirect_idx[i], 1);
                }

                int first_level_index = (sectors - INDIRECT_INDEX_RANGE) / 128;
                int second_level_index = (sectors - INDIRECT_INDEX_RANGE) % 128;
                disk_read(filesys_disk, disk_inode->double_indirect_idx, &single);
                for (i = 0; i < first_level_index; i++) {
                    disk_read(filesys_disk, single.entry[i], &doubly);
                    for (j = 0; j < 128; j++) {
                        free_map_release(doubly.entry[j], 1);
                    }
                    free_map_release(single.entry[i], 1);
                }

                if (second_level_index != 0) {
                    disk_read(filesys_disk, single.entry[first_level_index], &doubly);
                    for (j=0; j<second_level_index; j++) {
                        free_map_release(doubly.entry[j], 1);
                    }
                    free_map_release(single.entry[first_level_index], 1);
                }
                free_map_release(disk_inode->double_indirect_idx, 1);
              

            }
          free_map_release (inode->sector, 1);
          //free_map_release (inode->data.start,
                           // bytes_to_sectors (inode->data.length)); 
        }

      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
  //printf("removed\n");
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{

  
    //printf("inode_read_at\n");
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;

  

  while (size > 0) 
  {
     /* if (inode->writing_cnt > 0) {
          sema_down(&inode->sema);
          }*/
      if(offset > inode->data.length)
          return bytes_read;
      /* Disk sector to read, starting byte offset within sector. */
      disk_sector_t sector_idx = byte_to_sector_indexed (inode, offset, inode->data.length);
      //printf("sector_idx : %d\n", sector_idx);
      int sector_ofs = offset % DISK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = DISK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      read_in_cache(sector_idx, sector_ofs, buffer + bytes_read, chunk_size);      
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
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{

      //inode->writing_cnt++;
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;

  if (inode->deny_write_cnt)
    return 0;

  bool grow = (inode->data.length < offset+size);
  int newlength = offset+size;

  if (grow) {
      //printf("grow\n");
      lock_acquire(&inode->lock);
  }

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      disk_sector_t sector_idx = byte_to_sector_indexed (inode, offset, inode->data.length);
      //printf("@SECTOR %d\n", sector_idx);

      if (sector_idx == -1) {   //File grow
          int grow_bytes = offset+size - inode->data.length;
          if (grow_bytes > 0) {
              //lock_acquire(&(inode->lock));
              int sectors = bytes_to_sectors (offset + size);
              //printf("now %d grow to %d : allocate %d\n", inode_length(inode), offset+size, sectors);

              alloc_sectors_grow(inode, inode->sector, sectors, newlength);
              sector_idx = byte_to_sector_indexed (inode, offset,newlength);
              //printf("new sector_idx : %d\n", sector_idx);
              //lock_release(&(inode->lock));
          }
      }
      //printf("*** write to sector %d [offset : %d, size : %d]\n", sector_idx, offset, size);


      int sector_ofs = offset % DISK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      //off_t inode_left = inode_length (inode) - offset;
      int sector_left = DISK_SECTOR_SIZE - sector_ofs;
      //int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < sector_left ? size : sector_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE) 
        {
          /* Write full sector directly to disk. */
          write_to_cache (sector_idx, 0, buffer + bytes_written, DISK_SECTOR_SIZE, false);
        }
      else 
        {
            //printf("write : chunk_size %d, sector_idx %d\n", chunk_size, sector_idx);
          /* We don't need a bounce buffer anymore. */

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left) 
            write_to_cache(sector_idx, sector_ofs, buffer + bytes_written, chunk_size, true);
          else
            write_to_cache(sector_idx, sector_ofs, buffer + bytes_written, chunk_size, false);
        }

      /* Update length */
      if (inode_length(inode) < offset + chunk_size) {
          inode->data.length = offset + chunk_size;
          struct inode_disk *temp_disk = malloc(sizeof (struct inode_disk));
          inode_data_to_disk(temp_disk, &inode->data);
          disk_write(filesys_disk, inode->sector, temp_disk);
          free(temp_disk);
      }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }

  /*if (inode->writing_cnt-- == 1) {
      // Last writing thread should wake up reading thread 
      if (!list_empty(&inode->sema.waiters))
        sema_up(&inode->sema);
  }*/

  if (grow)
      lock_release(&inode->lock);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}
