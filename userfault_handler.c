#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <poll.h>
#include <sys/types.h>
#include <stdio.h>
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdint.h>

#include "userfault_handler.h"
#include "types.h"

static int page_size = 4096;

/**
 * @brief Fault handler thread
 *
 * @param arg
 *
 * @return
 */
void *
fault_handler_thread(void *arg)
{
	static struct uffd_msg msg;   /* Data read from userfaultfd */
	struct userfaultfd_thread_args* handler_arg = (struct
						userfaultfd_thread_args*)arg;
	long uffd;                    /* userfaultfd file descriptor */
	static char *page = NULL;
	struct uffdio_copy uffdio_copy;
	ssize_t nread;

	uffd = handler_arg->uffd;

	/* [H1: point 1]
	 * It the page pointer is NULL and hasn't been mapped before (see that
	 * they're static variables), let the kernel choose where to map the
	 * memory to, but make sure its size is page_size. Allow reading and
	 * writing to the page, the mapping is not backed by any file and is
	 * private to the process - not visible to other processes. FD is set to
	 * -1 since we're not backed by physical file anyway (-1 required for
	 * portability). Offset is 0. Exit with an error if we fail.
	 */
	if (page == NULL) {
		page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (page == MAP_FAILED)
			errExit("mmap");
	}

	for (;;) {

		/* See what poll() tells us about the userfaultfd */

		struct pollfd pollfd;
		int nready;
		/* [H3: point 1]
		 * Add uffd as the fd to poll. Wait for POLLIN event which means
		 * the fd has data to read - corresponding with uffd_msg
		 * structure becoming available due to access of registered
		 * memory. Exit with error if poll returns error code. Else,
		 * continue and print out if the POLLIN/POLLERR bits are set.
		 */
		pollfd.fd = uffd;
		pollfd.events = POLLIN;
		nready = poll(&pollfd, 1, -1);
		if (nready == -1)
			errExit("poll");

		/* [H4: point 1]
		 * Read data from the userfaultfd. This data with be of the type
		 * struct uffd_msg and will contain details such as the event,
		 * the fault flags, address of fault, userfault file descriptor
		 * of child process, old and new addresses of remapped area,
		 * original map length, start and end addresses of removed
		 * areas. Exit with fault if read returns -1. These are in a
		 * union so depending on the fault event, we look at the data
		 * with different representations.
		 */
		nread = read(uffd, &msg, sizeof(msg));
		if (nread == 0) {
			printf("EOF on userfaultfd!\n");
			exit(EXIT_FAILURE);
		}

		if (nread == -1)
			errExit("read");

		/* [H5: point 1]
		 * If the event is an event other than PAGEFAULT event, exit
		 * with an error as we do not handle other faults. There were
		 * multiple other faults added in 4.11.
		 */
		if (msg.event != UFFD_EVENT_PAGEFAULT) {
			fprintf(stderr, "Unexpected event on userfaultfd\n");
			exit(EXIT_FAILURE);
		}

		/* [H6: point 1]
		 * In the case it IS a PAGEFAULT event, print out the flags and
		 * the address.
		 */
//		printf("    UFFD_EVENT_PAGEFAULT event: ");
		printf("flags = %llx; ", msg.arg.pagefault.flags);
//		printf("address = %llx\n", msg.arg.pagefault.address);
		memset(page, 0, page_size);
	//	fault_cnt++;

		uffdio_copy.src = (unsigned long) page;
		uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address &
			~(page_size - 1);
		uffdio_copy.len = page_size;
		uffdio_copy.mode = 0;
		uffdio_copy.copy = 0;

		if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
			errExit("ioctl-UFFDIO_COPY");
		printf("\n[x]PAGEFAULT\n");

	//	printf("        (uffdio_copy.copy returned %lld)\n",
        //               uffdio_copy.copy);
	}
}

/**
 * @brief Sets up the pthread and user fault region
 *
 * @param start_region
 * @param length
 * @param thr
 * @param handler
 *
 * @return user fault fd
 */
long setup_userfaultfd_region(void* start_region, uint64_t length,
			     pthread_t* thr, void* (*handler)(void*), int sk)
{
	long uffd;          /* userfaultfd file descriptor */
	struct uffdio_api uffdio_api;
	struct uffdio_register uffdio_register;
	int pthread_ret;
	struct userfaultfd_thread_args* args =
		(struct userfaultfd_thread_args*)malloc(sizeof(struct
						userfaultfd_thread_args));
	args->sk = sk;

	uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);

	if (uffd == -1)
		errExit("userfaultfd");

	args->uffd = uffd;

	uffdio_api.api = UFFD_API;
	uffdio_api.features = 0;
	if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
		errExit("ioctl-UFFDIO_API");

	uffdio_register.range.start = (unsigned long) start_region;
	uffdio_register.range.len = length;
	uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
	if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
		errExit("ioctl-UFFDIO_REGISTER");

	pthread_ret = pthread_create(thr, NULL, handler, (void *) args);
	if (pthread_ret != 0) {
		errno = pthread_ret;
		errExit("pthread_create");
	}

	return uffd;
}


