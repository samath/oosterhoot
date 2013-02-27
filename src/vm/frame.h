#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <stdint.h>
#include "lib/kernel/list.h"
#include "vm/page.h"

enum frame_source
  {
    FRAME_ZERO,
    FRAME_MMAP,
    FRAME_SWAP
  };

/* Frame table entry */
struct frame
  {
    uint32_t *paddr;            // Physical address of this frame table entry
    struct list users;          // List of supplemental page entries that point to
                                // this frame. In this case, spe_list will have
                                // size at most two: the kernel and user page entries
    struct list_elem elem;      // For indexing in the main frame table list

    enum frame_source src;      // Whether the frame is in swap, mmaped, or should
                                // be zeroed out.
    void *aux;                  // An auxiliary address to keep track of the frame's
                                // location in swap space or the mmap table.

    bool ro;                    // Read-only
  };


void frame_init (void);
struct frame *frame_create (enum frame_source src, void *aux, bool ro);
void frame_free (struct frame *fte);
void frame_alloc (struct frame *fte, void *uaddr);
void frame_dealloc (struct frame *fte);

#endif
