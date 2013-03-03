#ifndef VM_MMAP_INFO_H
#define VM_MMAP_INFO_H

#include "lib/kernel/hash.h"
#include "threads/synch.h"
#include "lib/user/syscall_types.h"

struct mmap_table
{
  struct hash table;
  struct lock lock;
};

struct mmap_entry
{
  mapid_t map_id;     // Map id assigned by an mmap call.
  struct file *fp;
  struct file_map *fm;

  void *uaddr;        /* User-provided virtual address containing 
                         start of file */
  unsigned num_pages; // Number of consecutive pages containing file
  unsigned zero_bytes; 
                      // Number of bytes containing zero on last page

  struct hash_elem hash_elem; 
                      // For indexing into table by map_id
};

// Initialize an empty mmap_table for a new thread.
struct mmap_table *mmap_table_create (void);
// Return a stored mmap_entry for the given map_id, or none if none exist.
struct mmap_entry *mmap_table_lookup (struct mmap_table *mmt,
    mapid_t map_id);
// Insert a fully initialized entry into the mmap_table.
void mmap_table_insert (struct mmap_table *mmt, 
    struct mmap_entry *mme);
// Write mmap'd pages back to file, and remove the corresponding map_id.
void mmap_table_unmap (struct mmap_table *mmt, mapid_t map_id);
// Write all mmap'd pages back to file and free storage on thread death.
void mmap_table_destroy (void);

#endif
