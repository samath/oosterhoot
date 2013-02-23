#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stdint.h>
#include <stdbool.h>
#include "lib/kernel/hash.h"
#include "threads/synch.h"
#include "threads/thread.h"

enum supp_page_flags
  {
    SUPP_PAGE_TODO
  };

/* Supplemental page table entry */
struct supp_page
  {
    uint32_t *uaddr;            // Base user virtual address

    //bool rw;                  // Does page have read-write permissions
                                
                                // This is already a bit in the real page table

    uint8_t eviction_flags;     // Is this what the supp_page_flags is for?
                                // We need to keep track of what should happen
                                // during an eviction. Did it originate from
                                // a file with write permissions? Then it
                                // should be written back to disk, otherwise
                                // it should go to swap space.

                                // Maybe make this a frame flag? Then the frame code
                                // can handle it.

    struct hash_elem hash_elem; // For page table -> supp page table access
    struct list_elem list_elem; // For frame table -> supp page table access

    struct frame *frame;        // For supp page table -> frame table access
    struct thread *thread;       // For thread (-> supp page table) access
  };

struct supp_page_table
  {
    struct hash hash_table;
    struct lock lock;           // I'm using a coarse lock for eviction updates
                                // instead of a per-entry lock
  };

struct supp_page_table *supp_page_create (void);
#endif
