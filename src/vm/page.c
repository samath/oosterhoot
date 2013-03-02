#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"
#include "vm/page.h"

// ********************
// * Hash table helpers
// ********************

/* Use the base user virtual address as a simple hash. */
static unsigned
supp_page_hash (const struct hash_elem *e, void *aux UNUSED)
{
  return (unsigned) hash_entry (e, struct supp_page, hash_elem)->uaddr;
}

/* Compare base user virtual addresses to resolve hash collisions. */
static bool
supp_page_less (const struct hash_elem *a,  const struct hash_elem *b,
                void *aux UNUSED)
{
  return hash_entry (a, struct supp_page, hash_elem)->uaddr <
         hash_entry (b, struct supp_page, hash_elem)->uaddr;
}


/* Create a new supplemental page table for the current thread. */
struct supp_page_table *
supp_page_table_create (void)
{
  struct supp_page_table *spt = malloc (sizeof (struct supp_page_table));
  if (spt == NULL)
    PANIC ("Supplemental page table could not be allocated");

  hash_init (&spt->hash_table, supp_page_hash, supp_page_less, NULL);
  lock_init (&spt->lock);

  return spt;
}

void
supp_page_table_free (struct supp_page_table *spt)
{
  /* Reuse the list_elem, for wiring into the frame's users
     table, to collect all hash entries for freeing (can't
     free inside hash iteration). */
  struct list trash;
  list_init (&trash);
  
  struct hash_iterator iter;
  hash_first (&iter, &spt->hash_table);
  while (hash_next (&iter)) {
    struct supp_page *spe = hash_entry (hash_cur (&iter),
                            struct supp_page, hash_elem); 

    /* Either remove this from the users or free the frame */
    if (list_size (&spe->fte->users) > 1)
      list_remove (&spe->list_elem);
    else {
      frame_free (spe->fte);
    }

    list_push_back (&trash, &spe->list_elem);
  }

  /* Now actually free the entries */
  struct list_elem *e = list_begin (&trash);
  for (; e != list_end (&trash);) {
    struct supp_page *spe = list_entry (e,
                            struct supp_page, list_elem);

    e = list_next (e); // Advance before deleting
    supp_page_remove (spt, spe->uaddr); 
  }

  hash_destroy (&spt->hash_table, NULL);
  free (spt);
}


struct supp_page *
supp_page_lookup (struct supp_page_table *spt, void *uaddr)
{
  struct supp_page dummy_spe;
  dummy_spe.uaddr = pg_round_down (uaddr);

  struct hash_elem *result = 
      hash_find (&spt->hash_table, &dummy_spe.hash_elem);
  return result == NULL ? NULL : \
      hash_entry (result, struct supp_page, hash_elem);
}


/* Add a new entry to the supplemental page table. */
struct supp_page *
supp_page_insert (struct supp_page_table *spt, void *uaddr,
                  enum frame_source src, void *aux, bool ro)
{
  struct supp_page *spe = malloc (sizeof (struct supp_page));
  if (spe == NULL)
    PANIC ("Supplemental page entry could not be allocated");

  spe->uaddr = pg_round_down (uaddr);
  spe->fte = frame_create (src, (uint32_t) aux, ro);
  list_push_back (&spe->fte->users, &spe->list_elem);
  spe->thread = thread_current ();

  lock_acquire (&spt->lock);
  hash_insert (&spt->hash_table, &spe->hash_elem);
  lock_release (&spt->lock);

  return spe;
}

/* Remove an entry from the supplemental page table. */
void
supp_page_remove (struct supp_page_table *spt, void *uaddr)
{
  struct supp_page dummy_spe;
  dummy_spe.uaddr = pg_round_down (uaddr);

  lock_acquire (&spt->lock);
  struct supp_page *deleted = hash_delete (&spt->hash_table,
                                           &dummy_spe.hash_elem);
  lock_release (&spt->lock);

  ASSERT (deleted != NULL);
}


/* Obtains a physical frame to host the supplemental page table 
   entry's address. Updates the real page table with the mapping. */
void
supp_page_alloc (struct supp_page *spe)
{
  frame_alloc (spe->fte, spe->uaddr);
  pagedir_set_page (spe->thread->pagedir, spe->uaddr,
                    spe->fte->paddr, !spe->fte->ro);
}

