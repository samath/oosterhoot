#include "vm/swap.h"

struct swap_table *st;

//Initialization function to allocate teh swap table and setup the BLOCK_SWAP
//space on disk to swap memory in and out.
void
swap_init (void)
{
  block_sector_t num_sectors;

  //TODO check all mallocs!
  st = malloc(sizeof(struct swap_table));
  lock_init(&st->swap_table_lock);

  //Get the block that contains the swap space
  st->swap_block = block_get_role(BLOCK_SWAP);
  if(st->swap_block != NULL)
    num_sectors = block_size(st->swap_block);
  else
  {
    printf("swap_block = NULL in swap_init in swap.c\n");
  }
  
  //bitmap_create declared in bitmap.h. Allocates correct size.
  st->map = bitmap_create((size_t)num_sectors);
  if(st->map == NULL)
  {
    free(st);
    printf("st->map = NULL in swap_init in swap.c\n");
  }
}

//Swap out memory to the disk. The src_addr points to a page worth of user
//memory. This will be read into the swap space. The disk_block pointer
//will get set to the location at which the memory was stored.
void
swap_out (uint8_t *src_addr, block_sector_t *disk_block)
{
  lock_acquire(&st->swap_table_lock);
  //Find available space on disk in the swap space
  block_sector_t block_offset = bitmap_scan_and_flip(st->map, 0,
                                           PGSIZE/BLOCK_SECTOR_SIZE, false);
  if (block_offset == BITMAP_ERROR)
  {
    lock_release(&st->swap_table_lock);
    printf("page_idx = BITMAP_ERROR in swap_out() in swap.c\n");
    thread_exit();
  }
  //Update disk_block to the location on disk where the memory is being stored
  *disk_block = block_offset;  
  lock_release(&st->swap_table_lock);

  //TODO Not sure if this is right...
  ASSERT(block_offset % BLOCK_SECTOR_SIZE == 0);

  //write the memory from the src_addr onto the block
  int i = 0;
  for (i = 0; i<PGSIZE; i += BLOCK_SECTOR_SIZE)
  {
    block_write (st->swap_block, i + block_offset, src_addr + i);
  }
}
   
//Swap into memory from the disk. Swap_in must only be called if swap_out was
//previously called, and disk_block must be the same disk_block from swap_out.
//dest_addr should point to a page worth of memory to swap data into.
void
swap_in (uint8_t *dest_addr, block_sector_t *disk_block)
{
  int i = 0;
  block_sector_t block_offset = *disk_block;
  //Read in a page worth of memory
  for(i = 0; i<PGSIZE; i += BLOCK_SECTOR_SIZE)
  {
    block_read (st->swap_block, i + block_offset, dest_addr + i);
  }

  //Update the swap_table that this disk space is free again
  lock_acquire(&st->swap_table_lock);
  block_sector_t idx = bitmap_scan_and_flip(st->map, block_offset,
                                            PGSIZE/BLOCK_SECTOR_SIZE, true);
  //Assert that the page read in was previously marked as in use
  ASSERT(idx == block_offset);
  lock_release(&st->swap_table_lock);
}

//Free up a page of memory in the swap space. This should be called when a
//process with memory still in swap space has exited.
void
swap_delete(block_sector_t *disk_block)
{
  bitmap_set_multiple(st->map, *disk_block, PGSIZE/BLOCK_SECTOR_SIZE, false);
}
