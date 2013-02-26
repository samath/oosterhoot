#include "lib/kernel/list.h"
#include "lib/string.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"

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
  list_init (&fte->users); 

  return fte;
}

void
frame_free (struct frame *fte)
{
  ASSERT (fte->paddr != NULL);

  lock_acquire (&frame_lock);
  frame_dealloc (fte);
  list_remove (&fte->elem);
  lock_release (&frame_lock);

  free (fte);
}

/* Obtain a new frame using palloc_get_page and associate it with
   the frame table entry, appending the entry to the frame table.
   Also fills in the physical frame with the appropriate data, as
   specified by source. */
void
frame_alloc (struct frame *fte, uint32_t *aux, enum supp_page_source src)
{
  ASSERT (fte->paddr == NULL);
  fte->paddr = palloc_get_page (PAL_USER);

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
    //Requested memory is in swap space. Swap into page.
    case SUPP_PAGE_SWAP:
      swap_in (fte->paddr, (block_sector_t *)aux);
      break;
    default:
      PANIC ("Invalid frame source");
  }

  lock_acquire (&frame_lock);
  list_push_back (&frame_table, &fte->elem);
  lock_release (&frame_lock);
}


/* Returns the frame's physical memory to the user pool, and
   removes it from all supplemental page table entries.
   If the frame was mmapped, writes its data back to disk.
   Finally, removes the frame from the main fram table.
   This assumes the frame table has been locked already. */
void
frame_dealloc (struct frame *fte)
{
  struct list_elem *e = list_begin (&fte->users);
  for (; e != list_end (&fte->users); e = list_remove (e)) {
    struct supp_page *spe = list_entry (e, struct supp_page, list_elem);
    pagedir_clear_page (spe->thread->pagedir, spe->uaddr);
    spe->fte = NULL; 
  }

  /*
  if (fte->src == SUPP_PAGE_MMAP) {
    TODO
  } */

  list_remove (&fte->elem);
  palloc_free_page (fte->paddr);
}


