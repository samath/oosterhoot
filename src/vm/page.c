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

struct supp_page *
supp_page_lookup (struct supp_page_table *spt, void *uaddr)
{
  struct supp_page dummy_spe;
  dummy_spe.uaddr = pg_round_down (uaddr);

  struct hash_elem *result = hash_find (&spt->hash_table, &dummy_spe.hash_elem);
  return result == NULL ? NULL : \
      hash_entry (result, struct supp_page, hash_elem);
}


/* Add a new entry to the supplemental page table. */
struct supp_page *
supp_page_insert (struct supp_page_table *spt, void *uaddr,
                  enum supp_page_source src, bool ro)
{
  struct supp_page *spe = malloc (sizeof (struct supp_page));
  if (spe == NULL)
    PANIC ("Supplemental page entry could not be allocated");

  spe->uaddr = pg_round_down (uaddr);
  spe->src = src;
  spe->ro = ro;
  spe->fte = NULL;
  spe->thread = thread_current ();
  
  /* spe->aux = malloc(sizeof(uint32_t));
  if(spe->aux == NULL)
    PANIC ("Failed to malloc aux pointer in supplemental page entry"); */

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

  struct supp_page *deleted = hash_delete (&spt->hash_table,
                                           &dummy_spe.hash_elem);
  ASSERT (deleted != NULL);
}


/* Obtains a physical frame to host the supplemental page table 
   entry's address. Updates the real page table with the mapping. */
void
supp_page_alloc (struct supp_page *spe)
{
  ASSERT (spe->fte == NULL);

  spe->fte = frame_create ();
  list_push_back (&spe->fte->users, &spe->list_elem);
  frame_alloc (spe->fte, spe->src);
  
  pagedir_set_page (spe->thread->pagedir, spe->uaddr,
                    spe->fte->paddr, !spe->ro);
}


/* Removes the page entry from physical memory. Updates
   the real page table with the mapping. */
void
supp_page_dealloc (struct supp_page *spe)
{
  if (spe->fte == NULL) return;

  list_remove (&spe->list_elem);
  spe->fte = NULL;

  pagedir_clear_page (spe->thread->pagedir, spe->uaddr);
}