#include "vm/page.h"
#include "threads/malloc.h"


/* HASH TABLE HELPERS */

static unsigned mmap_hash (const struct hash_elem *e, void *aux UNUSED)
{
  return (unsigned) hash_entry (e, struct mmap_entry, hash_elem)->map_id;
}

static bool mmap_less (const struct hash_elem *a,
                       const struct hash_elem *b, void *aux UNUSED)
{
  return hash_entry (a, struct mmap_entry, hash_elem)->map_id <
         hash_entry (b, struct mmap_entry, hash_elem)->map_id; 
}

static void mmap_action_dispose (struct hash_elem *e, void *aux UNUSED)
{
  struct supp_page_table *spt = thread_current ()->spt;
  /* TODO
     this should have the same behavior as calling MUNMAP
     on each element in the mmap_table; see the related comment in
     syscall_munmap.
  */
}

/* END OF HASH TABLE HLEPERS */


// Return a pointer to a new empty mmap table.
struct mmap_table *mmap_table_create () 
{
  struct mmap_table *mmt = malloc (sizeof(struct mmap_table));
  if (mmt == NULL) PANIC ("Mmap table could not be allocated.");

  hash_init (&mmt->table, mmap_hash, mmap_less, NULL);

  return mmt;
}

// Return the mmap_entry for map_id, or NULL if none exists.
struct mmap_entry *mmap_table_lookup (struct mmap_table *mmt, 
                                      mapid_t map_id) 
{
  /* Construct a dummy entry for comparison.
     See related comment in page.c. */
  struct mmap_entry dummy;
  dummy.map_id = map_id;
  struct hash_elem *result = hash_find (&mmt->table, &dummy.hash_elem);
  return (result == NULL) ? NULL : 
    hash_entry (result, struct mmap_entry, hash_elem);
}

// Insert a new fully initialized mmap_entry into the table.
void mmap_table_insert (struct mmap_table *mmt, 
                        struct mmap_entry *mme)
{
  hash_insert (&mmt->table, &mme->hash_elem);
}

void mmap_table_remove (struct mmap_table *mmt, mapid_t map_id)
{
  struct mmap_entry *result = mmap_table_lookup (mmt, map_id);
  if (result == NULL) return;
  hash_delete (&mmt->table, &result->hash_elem);
}


void mmap_table_dispose () 
{
  hash_destroy (&thread_current ()->mmt->table, mmap_action_dispose);
}






