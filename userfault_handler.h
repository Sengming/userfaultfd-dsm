#ifndef __USERFAULT_HANDLER_H__
#define __USERFAULT_HANDLER_H__
#include <stdint.h>

void* fault_handler_thread(void *arg);
long setup_userfaultfd_region(void* start_region, uint64_t length,
			     pthread_t* thr, void* (*handler)(void*), int sk);

#endif
