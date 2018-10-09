#ifndef __TYPES_H__
#define __TYPES_H__

#include <stdint.h>

struct bus_thread_args
{
	int fd;
	uint64_t memory_address;
	uint64_t size;
};






#endif
