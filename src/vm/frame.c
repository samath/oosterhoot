#include "lib/kernel/list.h"
#include "lib/string.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"
#include "vm/mmap_table.h"
#include "userprog/file-map.h"
#include "filesys/file.h"

static struct list frame_table;
static struct lock frame_lock;

struct list_elem *clock_hand;

void
frame_init (void)
{
  list_init (&frame_table); 
  lock_init (&frame_lock);
  clock_hand = NULL;
}


/* Initilize a new frame table entry. */
struct frame *
frame_create (enum frame_source src, uint32_t aux, bool ro)
{
  struct frame *fte = malloc (sizeof (struct frame));
  if (fte == NULL)
    PANIC ("Frame could not be allocated");

  fte->paddr = NULL;
  fte->src = src;
  fte->aux = aux;
  fte->ro = ro;

  list_init (&fte->users); 
  lock_init (&fte->lock);
  return fte;
}

void
frame_free (struct frame *fte)
{
  if (fte->paddr != NULL) {
    lock_acquire (&frame_lock);
    frame_dealloc (fte);
    list_remove (&fte->elem);
    lock_release (&frame_lock);
  }

  free (fte);
}

/* Obtain a new frame using palloc_get_page and associate it with
   the frame table entry, appending the entry to the frame table.
   Also fills in the physical frame with the appropriate data, as
   specified by source. */
void
frame_alloc (struct frame *fte, void *uaddr)
{
  ASSERT (fte->paddr == NULL);

  lock_acquire(&fte->lock);
  
  /* Try to get page. If out of memory, evict a page and try again */
  while ((fte->paddr = palloc_get_page (PAL_USER)) == NULL)
  {
   eviction();
  }

  struct mmap_entry *mme;
  
  switch (fte->src) {
    case FRAME_ZERO:
      memset (fte->paddr, 0, PGSIZE);
      break;
    case FRAME_MMAP:
      /* Fill in the physical memory for the frame with the data */
      mme = (struct mmap_entry *) fte->aux;
      unsigned offset = (unsigned) uaddr - (unsigned) mme->uaddr;

      struct file_with_lock fwl = fwl_from_fd (mme->fm, (int) mme->map_id);
      if (fwl.lock) lock_acquire (fwl.lock);
      if (offset / PGSIZE < mme->num_pages - 1 || mme->zero_bytes == 0) {
        file_read_at (mme->fp, fte->paddr, PGSIZE, offset);
      } else {
        file_read_at (mme->fp, fte->paddr, PGSIZE - mme->zero_bytes, offset);
        memset ((char *)fte->paddr + PGSIZE - mme->zero_bytes, 
                     0, mme->zero_bytes);
      }
      if (fwl.lock) lock_release (fwl.lock);

      break;
    case FRAME_SWAP:
      swap_in (fte->paddr, (block_sector_t *) &fte->aux);
      break;
    default:
      PANIC ("Invalid frame source");
  }

  lock_acquire (&frame_lock);
  list_push_back (&frame_table, &fte->elem);
  lock_release (&frame_lock);
  lock_release (&fte->lock);

}


/* Returns the frame's physical memory to the user pool.
   If the frame was mmapped, writes its data back to disk.
   Finally, removes the frame from the main frame table.
   This assumes the frame table has been locked already. */
void
frame_dealloc (struct frame *fte)
{
  lock_acquire(&fte->lock);
  struct list_elem *e = list_begin (&fte->users);
  for (; e != list_end (&fte->users); e = list_remove (e)) {
    struct supp_page *spe = list_entry (e, struct supp_page, list_elem);

    /* Write to mmapped file if necessary */
    if (fte->src == FRAME_MMAP && !fte->ro &&
        ((struct mmap_entry *)fte->aux)->fm && /* check if data segment */
        pagedir_is_dirty (spe->thread->pagedir, spe->uaddr)) {
      struct mmap_entry *mme = (struct mmap_entry *) fte->aux;
      unsigned page_num = 
          ((unsigned) spe->uaddr - (unsigned) mme->uaddr) / PGSIZE;
      unsigned bytes = (page_num == mme->num_pages - 1) ? 
          PGSIZE - mme->zero_bytes : PGSIZE;
      
      struct file_with_lock fwl = fwl_from_fd (mme->fm, (int) mme->map_id);
      if (fwl.lock) lock_acquire (fwl.lock);
      file_write_at (mme->fp, spe->uaddr, bytes, page_num * PGSIZE);
      if (fwl.lock) lock_release (fwl.lock);
    }
    /* Write to swap space */
    else if (!fte->ro && pagedir_is_dirty (spe->thread->pagedir, spe->uaddr))
    {
      fte->src = FRAME_SWAP;
      swap_out(fte->paddr, (block_sector_t *) &fte->aux);
    }
    /* In all other cases, no need to write memory back to disk. */

    pagedir_clear_page (spe->thread->pagedir, spe->uaddr);
  }
  list_remove (&fte->elem);
  palloc_free_page (fte->paddr);
  fte->paddr = NULL;
  lock_release(&fte->lock);
}

/* Runs the eviction process, looping through all the frame entries searching
   for a frame that has not been accessed recently and deallocating it, making
   room for a new page to be brought into memory. */
void
eviction(void)
{
  /* Eviction should never be called if the frame_table is empty */
  ASSERT(!list_empty(&frame_table));
  ASSERT(list_size(&frame_table) > 1);
  if(clock_hand == NULL)
    clock_hand = list_begin(&frame_table);

  struct list_elem *e;
  struct supp_page *spe;
  struct frame *fte;
  bool dealloc = true;

  /* Keep looping through frames until we find one to evict */
  while(true)
  {
    fte = list_entry(clock_hand, struct frame, elem);
    e = list_begin(&fte->users);
    dealloc = true;
    for (; e != list_end (&fte->users); e = list_next (e))
    {
      spe = list_entry (e, struct supp_page, list_elem);
      /* If page has been accessed, do not dealloc frame. */
      if(pagedir_is_accessed(spe->thread->pagedir, spe->uaddr))
      {
        dealloc = false;
        pagedir_set_accessed(spe->thread->pagedir, spe->uaddr, false);
      }
    }

    /* Move clock hand to next frame in the list */
    clock_hand = list_next(clock_hand);
    if(clock_hand == list_end(&frame_table))
      clock_hand = list_begin(&frame_table);


    if(dealloc && !fte->pinned)
    {
      frame_dealloc(fte);
      break;
    }
  }
}
