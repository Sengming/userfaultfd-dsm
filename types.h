#ifndef __TYPES_H__
#define __TYPES_H__

#include <stdint.h>
#include <pthread.h>
#include <stdbool.h>

#define INPUT_CMD_LEN (20)
#define MAX_PAGES     (100)
#define WRITE_BUF_LEN (100)
#define READ_BUF_LEN  (100)

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE);	\
	} while (0)

enum msi_tag
{
	INVALID = 0,
	MODIFIED,
	SHARED,
	NUM_TAGS
};

struct msi_page
{
	enum msi_tag tag;
	pthread_mutex_t mutex;
	void* start_address;
	void* physical_address;
	bool in_use;
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
	uint64_t physical_address;
	long uffd;
};




#endif
