#ifndef __LIB_USER_SYSCALL_TYPES_H
#define __LIB_USER_SYSCALL_TYPES_H

/* Process identifier */
typedef int pid_t;
#define PID_ERROR ((pid_t) -1)

/* Map region identifier. */
typedef int mapid_t;
#define MAP_FAILED ((mapid_t) -1)

#endif
