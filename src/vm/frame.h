#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <stdint.h>
#include "lib/kernel/list.h"
#include "vm/page.h"

enum frame_flags
  {
    FRAME_TODO
  };

/* Frame table entry */
struct frame
  {
    uint32_t *paddr;            // Physical address of this frame table entry
    struct list users;       // List of supplemental page entries that point to
                                // this frame. In this case, spe_list will have
                                // size at most two: the kernel and user page entries
    struct list_elem elem;      // For indexing in the main frame table list
  };


void frame_init (void);
struct frame *frame_create (void);
void frame_free (struct frame *fte);
void frame_alloc (struct frame *fte, uint32_t *aux, enum supp_page_source src);
void frame_dealloc (struct frame *fte);

#endif
