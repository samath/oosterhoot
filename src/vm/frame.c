#include "lib/kernel/list.h"
#include "lib/string.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"
#include "vm/mmap_table.h"
#include "filesys/file.h"

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
frame_create (enum frame_source src, void *aux, bool ro)
{
  struct frame *fte = malloc (sizeof (struct frame));
  if (fte == NULL)
    PANIC ("Frame could not be allocated");

  fte->paddr = NULL;
  fte->src = src;
  fte->aux = aux;
  fte->ro = ro;

  list_init (&fte->users); 

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
  fte->paddr = palloc_get_page (PAL_USER);

  /* TODO: implement eviction instead of panic */
  if (fte->paddr == NULL)
    PANIC ("Unable to allocate a new frame for this entry");

  struct mmap_entry *mme;
  
  switch (fte->src) {
    case FRAME_ZERO:
      memset (fte->paddr, 0, PGSIZE);
      break;
    case FRAME_MMAP:
      /* Fill in the physical memory for the frame with the data */
      mme = (struct mmap_entry *) fte->aux;
      unsigned offset = (unsigned) uaddr - (unsigned) mme->uaddr;
      
      if (offset / PGSIZE < mme->num_pages - 1 || mme->zero_bytes == 0) {
        file_read_at (mme->fp, fte->paddr, PGSIZE, offset);
      } else {
        file_read_at (mme->fp, fte->paddr, PGSIZE - mme->zero_bytes, offset);
        memset ((char *)fte->paddr + PGSIZE - mme->zero_bytes, 
                     0, mme->zero_bytes);
      }
      break;
    case FRAME_SWAP:
      swap_in (fte->paddr, (block_sector_t *) fte->aux);
      break;
    default:
      PANIC ("Invalid frame source");
  }

  lock_acquire (&frame_lock);
  list_push_back (&frame_table, &fte->elem);
  lock_release (&frame_lock);
}


/* Returns the frame's physical memory to the user pool.
   If the frame was mmapped, writes its data back to disk.
   Finally, removes the frame from the main frame table.
   This assumes the frame table has been locked already. */
void
frame_dealloc (struct frame *fte)
{
  struct list_elem *e = list_begin (&fte->users);
  for (; e != list_end (&fte->users); e = list_remove (e)) {
    struct supp_page *spe = list_entry (e, struct supp_page, list_elem);

    /* Write to mmapped file if necessary */
    if (fte->src == FRAME_MMAP &&
        pagedir_is_dirty (spe->thread->pagedir, spe->uaddr)) {
      struct mmap_entry *mme = (struct mmap_entry *) fte->aux;
      unsigned page_num = 
          ((unsigned) spe->uaddr - (unsigned) mme->uaddr) / PGSIZE;
      unsigned bytes = (page_num == mme->num_pages - 1) ? 
          PGSIZE - mme->zero_bytes : PGSIZE;
      file_write_at (mme->fp, spe->uaddr, bytes, page_num * PGSIZE);
    }

    pagedir_clear_page (spe->thread->pagedir, spe->uaddr);
    spe->fte = NULL;
  }

  list_remove (&fte->elem);
  palloc_free_page (fte->paddr);
}


