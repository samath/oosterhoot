#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stdint.h>
#include "lib/kernel/hash.h"
#include "threads/synch.h"
#include "threads/thread.h"

enum supp_page_source
  {
    SUPP_PAGE_ZERO, 
    SUPP_PAGE_MMAP,
    SUPP_PAGE_SWAP
  };

/* Supplemental page table entry */
struct supp_page
  {
    uint32_t *uaddr;            // Base user virtual address
   
    uint32_t *aux;              // An auxiliary pointer to keep track of a
                                // frame's location in either swap space or
                                // the mmap table

    bool ro;                    // Read Only

    enum supp_page_source src;  // Whether this page is in swap, mmaped, or
                                // is not yet initialized

    struct hash_elem hash_elem; // For page table -> supp page table access
    struct list_elem list_elem; // For frame table -> supp page table access

    struct frame *fte;          // For supp page table -> frame table access
    struct thread *thread;      // For thread (and thus supp page table) access
  };

struct supp_page_table
  {
    struct hash hash_table;
    struct lock lock;           // I'm using a coarse lock for eviction updates
                                // instead of a per-entry lock
  };

struct supp_page_table *supp_page_table_create (void);
struct supp_page *supp_page_lookup (struct supp_page_table *spt,
  void *uaddr);
struct supp_page *supp_page_insert (struct supp_page_table *spt,
  void *uaddr, enum supp_page_source src, bool ro); 
void supp_page_remove (struct supp_page_table *spt,
  void *uaddr);
void supp_page_alloc (struct supp_page *spe);
void supp_page_dealloc (struct supp_page *spe);

#endif
