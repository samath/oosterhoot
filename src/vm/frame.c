#include "vm/frame.h"
#include "vm/page.h"
#include "lib/kernel/list.h"
#include "lib/string.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"

static struct list frame_table;
static struct lock frame_lock;

void
frame_init (void)
{
  list_init (&frame_table); 
  lock_init (&frame_lock);
}


/* Initilize a new frame table entry. */
struct frame *
frame_create (void)
{
  struct frame *fte = malloc (sizeof (struct frame));
  if (fte == NULL)
    PANIC ("Frame could not be allocated");

  fte->paddr = NULL;
  list_init (&fte->spe_list); 

  return fte;
}

/* Obtain a new frame using palloc_get_page and associate it with
   the frame table entry, appending the entry to the frame table.
   Also fills in the physical frame with the appropriate data, as
   specified by source. */
void
frame_alloc (struct frame *fte, enum supp_page_source src)
{
  ASSERT (fte->paddr == NULL);
  fte->paddr = palloc_get_page (PAL_USER|PAL_ZERO);

  /* TODO: implement eviction instead of panic */
  if (fte->paddr == NULL)
    PANIC ("Unable to allocate a new frame for this entry");

  /* Fill in the physical memory for the frame with the data */
  switch (src) {
    case SUPP_PAGE_ZERO:
      memset (fte->paddr, 0, PGSIZE);
      break;
    case SUPP_PAGE_MMAP:
      /* TODO */
      break;
    case SUPP_PAGE_SWAP:
      /* TODO */
      break;
    default:
      PANIC ("Invalid frame source");
  }

  lock_acquire (&frame_lock);
  list_push_back (&frame_table, &fte->elem);
  lock_release (&frame_lock);
}

void
frame_free (struct frame *fte)
{
  ASSERT (fte->paddr != NULL);
  palloc_free_page (fte->paddr);  
  list_remove (&fte->elem);
  free (fte);
}

