#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stdint.h>
#include "lib/kernel/hash.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "vm/frame.h"

enum frame_source;

/* Supplemental page table entry */
struct supp_page
  {
    uint32_t *uaddr;            // Base user virtual address

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
  void *uaddr, enum frame_source src, void *aux, bool ro); 
void supp_page_remove (struct supp_page_table *spt,
  void *uaddr);
void supp_page_alloc (struct supp_page *spe);
void supp_page_dealloc (struct supp_page *spe);

#endif
