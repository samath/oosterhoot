#include "threads/vaddr.h"
#include "threads/malloc.h"
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
supp_page_create (void)
{
  struct supp_page_table *spt = malloc (sizeof (struct supp_page_table));
  if (spt == NULL)
    PANIC ("Supplemental page table could not be allocated");

  hash_init (&spt->hash_table, supp_page_hash, supp_page_less, NULL);
  lock_init (&spt->lock);

  return spt;
}


