#include "vm/page.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "threads/vaddr.h"
#include "vm/frame.h"

static struct mmap_entry *lookup (struct mmap_table * mmt, mapid_t map_id);

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
  struct mmap_entry *mme = hash_entry (e, struct mmap_entry, hash_elem);
  struct supp_page_table *spt = thread_current ()->spt;

  unsigned i = 0;
  for(; i < mme->num_pages; i++) {
    void *uaddr = (char *) mme->uaddr + i * PGSIZE;
    struct supp_page *sp = supp_page_lookup (spt, uaddr);
    if (sp->fte != NULL) {
      frame_free (sp->fte);
    }
    supp_page_remove (spt, uaddr);
  }
  
  close_fd (mme->fm, (int) mme->map_id);
  hash_delete (&thread_current ()->mmt->table, e);

}

/* END OF HASH TABLE HLEPERS */


// Return a pointer to a new empty mmap table.
struct mmap_table *mmap_table_create () 
{
  struct mmap_table *mmt = malloc (sizeof(struct mmap_table));
  if (mmt == NULL) PANIC ("Mmap table could not be allocated.");

  hash_init (&mmt->table, mmap_hash, mmap_less, NULL);
  lock_init (&mmt->lock);

  return mmt;
}

struct mmap_entry *mmap_table_lookup (struct mmap_table *mmt, mapid_t map_id)
{
  lock_acquire (&mmt->lock);
  struct mmap_entry *mme = lookup (mmt, map_id);
  lock_release (&mmt->lock);
  return mme;
}

// Return the mmap_entry for map_id, or NULL if none exists.
static struct mmap_entry *lookup (struct mmap_table *mmt, 
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
  lock_acquire (&mmt->lock);
  hash_insert (&mmt->table, &mme->hash_elem);
  lock_release (&mmt->lock);
}

void mmap_table_unmap (struct mmap_table *mmt, mapid_t map_id) 
{
  lock_acquire (&mmt->lock);
  struct mmap_entry *mme = lookup (mmt, map_id);
  if (mme == NULL) {
    lock_release (&mmt->lock);
    return;
  }
  mmap_action_dispose (&mme->hash_elem, NULL);
  lock_release (&mmt->lock);
}


void mmap_table_destroy () 
{
  hash_destroy (&thread_current ()->mmt->table, mmap_action_dispose);
  free (thread_current ()->mmt);
}

