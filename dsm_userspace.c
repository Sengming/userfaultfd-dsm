#define _GNU_SOURCE
#include <sys/types.h>
#include <stdio.h>
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <arpa/inet.h>

#include "messages.h"
#include "types.h"
#include "bus_functions.h"
#include "userfault_handler.h"

#define TOTAL_NUM_ARGS		(4)


//static int page_size;

int
main(int argc, char *argv[])
{
	int socket_fd;
	char fgets_buffer[100];

	/* Bus thread related */
	struct bus_thread_args bus_args;
	pthread_t bus_thread;
	int bus_thread_ret;

	/* User fault thread related */
	struct mmap_args shared_mapping;
	pthread_t userfaultfd_thread;

	int exit_write_ret;

	/* Message */
	struct msi_message msg;

	if (argc != TOTAL_NUM_ARGS) {
		fprintf(stderr, "Usage: %s my_port remote_ip remote_port\n",
			argv[0]);
		exit(EXIT_FAILURE);
	}
	/* Create client first and try to connect. If other server doesn't
	 * exist, then we are the first node. Else, we are the second node. */
	socket_fd = try_connect_client(atoi(argv[3]), argv[2], &bus_args,
				       &shared_mapping);

	if (socket_fd > 0){
		/* We have successfully connected and have a socket fd*/
		mmap(shared_mapping.memory_address, shared_mapping.len,
		     PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS |
		     MAP_FIXED, -1, 0);

		bus_thread_ret = pthread_create(&bus_thread, NULL,
					     bus_thread_handler,
					     (void *) &bus_args);
		if (bus_thread_ret != 0) {
			errno = bus_thread_ret;
			errExit("pthread_create");
		}
	} else {
	/* There is no server to connect to so we set up ourselves as the server*/
		socket_fd = setup_server(atoi(argv[1]), &bus_args,
					 &shared_mapping);
		bus_thread_ret = pthread_create(&bus_thread, NULL,
					     bus_thread_handler,
					     (void *) &bus_args);
		if (bus_thread_ret != 0) {
			errno = bus_thread_ret;
			errExit("pthread_create");
		}
	}
	setup_userfaultfd_region(shared_mapping.memory_address,
				 shared_mapping.len, &userfaultfd_thread,
				 &fault_handler_thread, socket_fd);


	/* Prompt User for Command */
	for(;;) {
		printf("What would you like to do? (R)ead/(w)rite/E(x)it?: ");
		if (!fgets(fgets_buffer, INPUT_CMD_LEN, stdin))
			errExit("fgets error");

		if (!strncmp(fgets_buffer, "x", 1)){
			pthread_cancel(bus_thread);
			msg.message_type = DISCONNECT;
			exit_write_ret = write(socket_fd, &msg, sizeof(msg));
			if (exit_write_ret <= 0) {
				errExit("Exit Write Error");
			}
			goto exit_success;
		}
		else if (!strncmp(fgets_buffer, "w", 1)){
			memset(shared_mapping.memory_address, '@', 1024);
			printf("#5. write address %p in main(): ",
			       shared_mapping.memory_address);
		}
	}

exit_success:
	printf("EXITING");
	exit(EXIT_SUCCESS);
}
