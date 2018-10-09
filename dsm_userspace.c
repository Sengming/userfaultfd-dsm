/* userfaultfd_demo.c

   Licensed under the GNU General Public License version 2 or later.
*/
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
#include <poll.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include "messages.h"
#include "types.h"

#define INPUT_CMD_LEN (20)

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE);	\
	} while (0)

//static int page_size;

static void* bus_thread_handler(void* arg)
{
	int rd;
	struct msi_message msg;
	struct bus_thread_args* bus_args = arg;

	if (!bus_args)
		errExit("Null Pointer");

	while (1) {
		rd = read(bus_args->fd, &msg, sizeof(msg));
		if (rd < 0)
			errExit("Read Error");
		if (msg.message_type == CONNECTION_ESTABLISHED) {
			printf("Pairing Request Received: Addr: %lu Length: %lu\n"
			       ,msg.payload.memory_pair.address,
			       msg.payload.memory_pair.size);
		}
	}
	return NULL;
}

static int setup_server(int port, struct bus_thread_args* arg_output)
{
	/* Socket related variables */
	int sk, ret;
	int ask;
	int len;
	struct sockaddr_in addr;
	/* mmap related */
	char command[INPUT_CMD_LEN];
	int page_size;
	void* mmap_ptr;
	int write_ret;

	struct msi_message msg;

	sk = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sk < 0) {
		errExit("Socket Creation");
	}
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(port);

	ret = bind(sk, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		errExit("Server bind failed");
	}

	ret = listen(sk, 16);
	if (ret < 0) {
		errExit("Server listen failed");
	}

	printf("Waiting for connections\n");

	ask = accept(sk, NULL, NULL);
	if (ask < 0) {
		errExit("Server accept failed");
	}

	/* Prompt User for mmap memory */
	printf("How many pages to mmap?");
	if (!fgets(command, INPUT_CMD_LEN, stdin)){
		errExit("fgets error");
	}

	page_size = sysconf(_SC_PAGE_SIZE);
	len = strtoul(command, NULL, 0) * page_size;
	if (len < 0)
		errExit("strtoul_server_setup");

	mmap_ptr = mmap(NULL, len, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mmap_ptr == MAP_FAILED)
		errExit("mmap");

	/* Populate Message fields before sending */
	msg.message_type = CONNECTION_ESTABLISHED;
	msg.payload.memory_pair.address = (uint64_t)mmap_ptr;
	msg.payload.memory_pair.size = len;
	write_ret = write(ask, &msg , sizeof(msg));
	if (write_ret <= 0) {
		errExit("Server initial write error");
	}

	/* Populate argument fields for worker thread */
	arg_output->fd = ask;
	arg_output->memory_address = (uint64_t)mmap_ptr;
	arg_output->size = len;

	/* We've paired, no longer any need for sk */
	close(sk);

	return ask;
}

static int try_connect_client(int port, char* ip_string, struct
			      bus_thread_args* arg_output)
{
	int sk = 0;
	int err = 0;
	struct sockaddr_in addr;

	sk = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sk < 0) {
		goto out_socket_err;
	}

	printf("Connecting to %s:%d\n", ip_string, port);
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	err = inet_aton(ip_string, &addr.sin_addr);
	if (err < 0) {
		goto out_close_socket;
	}

	addr.sin_port = htons(port);

	err = connect(sk, (struct sockaddr *)&addr, sizeof(addr));
	if (err < 0) {
		goto out_close_socket;
	}

	arg_output->fd = sk;
	/* Return the socket if we successfully connect to it*/
	return sk;

out_close_socket:
	close(sk);
out_socket_err:
	return -1;
}

int
main(int argc, char *argv[])
{
	//struct uffdio_api uffdio_api;
	//struct uffdio_register uffdio_register;
	int socket_fd;
	char fgets_buffer[100];
	struct bus_thread_args bus_args;
	pthread_t bus_thread;
	int pthread_ret;

	if (argc != 4) {
		fprintf(stderr, "Usage: %s my_port remote_ip remote_port\n",
			argv[0]);
		exit(EXIT_FAILURE);
	}
	/* Create client first and try to connect. If other server doesn't
	 * exist, then we are the first node. Else, we are the second node. */
	socket_fd = try_connect_client(atoi(argv[3]), argv[2], &bus_args);

	if (socket_fd > 0){
		/* We have successfully connected and have a socket fd*/

		pthread_ret = pthread_create(&bus_thread, NULL,
					     bus_thread_handler,
					     (void *) &bus_args);
		if (pthread_ret != 0) {
			errno = pthread_ret;
			errExit("pthread_create");
		}
	} else {
	/* There is no server to connect to so we set up ourselves as the server*/
		setup_server(atoi(argv[1]), &bus_args);
		pthread_ret = pthread_create(&bus_thread, NULL,
					     bus_thread_handler,
					     (void *) &bus_args);
		if (pthread_ret != 0) {
			errno = pthread_ret;
			errExit("pthread_create");
		}
	}


	/* Prompt User for Command */
	for(;;) {
		printf("What would you like to do? Read/Write?");
		if (!fgets(fgets_buffer, INPUT_CMD_LEN, stdin)){
			errExit("fgets error");
		}
	}
//	uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
//	if (uffd == -1)
//		errExit("userfaultfd");
//
//	uffdio_api.api = UFFD_API;
//	uffdio_api.features = 0;
//	if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
//		errExit("ioctl-UFFDIO_API");

//	uffdio_register.range.start = (unsigned long) addr;
//	uffdio_register.range.len = len;
//	uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
//	if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
//		errExit("ioctl-UFFDIO_REGISTER");
//
//	s = pthread_create(&thr, NULL, fault_handler_thread, (void *) uffd);
//	if (s != 0) {
//		errno = s;
//		errExit("pthread_create");
//	}
	printf("EXITING");
	exit(EXIT_SUCCESS);
}
