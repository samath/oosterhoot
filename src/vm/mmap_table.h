#ifndef VM_MMAP_INFO_H
#define VM_MMAP_INFO_H

#include "lib/kernel/hash.h"
#include "lib/user/syscall_types.h"

struct mmap_table
{
  struct hash table;
};

struct mmap_entry
{
  mapid_t map_id;    // Map id assigned by an mmap call.
  int fd;             // File descriptor
  struct file *fp;

  void *uaddr;        /* User-provided virtual address containing 
                         start of file */
  unsigned num_pages; // Number of consecutive pages containing file
  unsigned zero_bytes; 
                      // Number of bytes containing zero on last page

  struct hash_elem hash_elem; 
                      // For indexing into table by map_id
};

struct mmap_table *mmap_table_create (void);
struct mmap_entry *mmap_table_lookup (struct mmap_table *mmt,
    mapid_t map_id);
void mmap_table_insert (struct mmap_table *mmt, 
    struct mmap_entry *mme);
void mmap_table_remove (struct mmap_table *mmt,
    mapid_t map_id);
void mmap_table_dispose (void);

#endif
