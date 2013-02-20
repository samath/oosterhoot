#include "vm/frame.h"
#include "lib/kernel/list.h"
#include "threads/malloc.h"
#include "threads/palloc.h"

static struct list frame_table;

void
frame_init (void)
{
  list_init (&frame_table); 
}


/* Initilize a new frame table entry. */
struct frame *
frame_create (void)
{
  struct frame *fte = malloc (sizeof (struct frame));
  if (fte == NULL)
    PANIC ("Frame could not be allocated");

  fte->paddr = NULL;
  list_init (&fte->spte_list); 

  return fte;
}

/* Obtain a new frame using palloc_get_page and associate it with
   the frame table entry. This appends the entry to the frame table. */
void
frame_alloc (struct frame *fte)
{
  ASSERT (fte->paddr == NULL);
  fte->paddr = palloc_get_page (PAL_USER|PAL_ZERO);

  /* todo: implement swapping */
  if (fte->paddr == NULL)
    PANIC ("Unable to allocate a new frame for this entry");

  list_push_back (&frame_table, &fte->elem);
}


void
frame_free (struct frame *fte)
{
  ASSERT (fte->paddr != NULL);
  palloc_free_page (fte->paddr);  
  list_remove (&fte->elem);
  free (fte);
}

