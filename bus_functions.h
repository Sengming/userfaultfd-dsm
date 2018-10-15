#ifndef __BUS_FUNCTIONS_H__
#define __BUS_FUNCTIONS_H__
#include "messages.h"
#include "types.h"
#include <sys/socket.h>
#include <linux/types.h>
#include <arpa/inet.h>

int setup_server(int port, struct bus_thread_args* arg_output, struct mmap_args*
		 mmap_output);
int try_connect_client(int port, char* ip_string, struct
			      bus_thread_args* arg_output, struct mmap_args*
			      mmap_output);
void* bus_thread_handler(void* arg);

#endif
