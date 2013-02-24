#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <stdint.h>
#include <stdio.h>
#include <bitmap.h>
#include "devices/block.h"
#include "threads/synch.h"

//swap_table holds information for the BLOCK_SWAP bitmap
struct swap_table
  {
    struct bitmap *map;
    struct block *swap_block;
    struct lock swap_table_lock;
  };

void swap_init (void);
void swap_in (uint8_t *dest_addr, block_sector_t *disk_block);
void swap_out (uint8_t *src_addr, block_sector_t *disk_block);

void swap_delete(block_sector_t *disk_block);

#endif /* vm/swap.h */
