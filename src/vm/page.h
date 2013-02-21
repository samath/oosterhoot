#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stdint.h>
#include <stdbool.h>
#include "lib/kernel/hash.h"
#include "threads/synch.h"

enum supp_page_flags
  {
    SUPP_PAGE_TODO
  };

/* Supplemental page table entry */
struct supp_page
  {
    struct frame *frame;        // Pointer to the frame table entry
    uint32_t *pte;              // Pointer to the main page table entry
    bool rw;                    // Does page have read-write permissions

    uint8_t eviction_flags;     // Is this what the supp_page_flags is for?
                                // We need to keep track of what should happen
                                // during an eviction. Did it originate from
                                // a file with write permissions? Then it
                                // should be written back to disk, otherwise
                                // it should go to swap space.

    struct hash_elem hash_elem; // For page table -> supp page table access

    struct lock spe_lock;       // Need to lock page entry during eviction
                                // and when bringing in frame to memory.
                                // Can put lock here if we only ever access
                                // frames from the user page table. Otherwise
                                // this lock should probably go in frame?
  };

#endif
