#ifndef __TYPES_H__
#define __TYPES_H__

#include <stdint.h>
#include <pthread.h>

#define INPUT_CMD_LEN (20)

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE);	\
	} while (0)


enum msi_tag
{
	INVALID = 0,
	MODIFIED,
	SHARED,
	NUM_TAGS
};

struct page_state
{
	enum msi_tag tag;
	pthread_mutex_t mutex;
};

struct bus_thread_args
{
	int fd;
	uint64_t memory_address;
	uint64_t len;
};

struct mmap_args
{
	void* memory_address;
	uint64_t len;
};

struct userfaultfd_thread_args
{
	int sk;
	long uffd;
};




#endif
