#ifndef USERPROG_FILE_MAP
#define USERPROG_FILE_MAP

#include <stdio.h>
#include "threads/synch.h"


enum fm_mode {
  FM_MODE_FD,
  FM_MODE_MMAP
};

struct file_map;
struct file_with_lock {
  struct file *fp;
  struct lock *lock;
  enum fm_mode mode;
};

struct file_map * init_file_map (void);
void destroy_file_map (struct file_map *fm);

/* Return the file to which a file descriptor refers. */
struct file_with_lock fwl_from_fd (struct file_map *fm, int fd);
/* Return an unused file descriptor for f. */
int get_new_fd (struct file_map *fm, struct file *f, enum fm_mode mode);
/* Close a given file descriptor. 
   If the file has no remaining descriptors, close the file. */
void close_fd (struct file_map *fm, int fd);

/* Close all file descriptors belonging to current thread. */
void close_fd_for_thread (struct file_map *fm);

#endif
