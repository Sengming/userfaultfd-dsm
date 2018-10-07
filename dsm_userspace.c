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

#define INPUT_CMD_LEN (20)
#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE);	\
	} while (0)

static int page_size;

//static void *
//fault_handler_thread(void *arg)
//{
//	static struct uffd_msg msg;   /* Data read from userfaultfd */
//	static int fault_cnt = 0;     /* Number of faults so far handled */
//	long uffd;                    /* userfaultfd file descriptor */
//	static char *page = NULL;
//	struct uffdio_copy uffdio_copy;
//	ssize_t nread;
//
//	uffd = (long) arg;
//
//	/* [H1: point 1]
//	 * It the page pointer is NULL and hasn't been mapped before (see that
//	 * they're static variables), let the kernel choose where to map the
//	 * memory to, but make sure its size is page_size. Allow reading and
//	 * writing to the page, the mapping is not backed by any file and is
//	 * private to the process - not visible to other processes. FD is set to
//	 * -1 since we're not backed by physical file anyway (-1 required for
//	 * portability). Offset is 0. Exit with an error if we fail.
//	 */
//	if (page == NULL) {
//		page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
//			    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
//		if (page == MAP_FAILED)
//			errExit("mmap");
//	}
//
//	/* [H2: point 1]
//	 * Have poll continuously monitor the userfaultfd for events. This is
//	 * the main thread loop.
//	 */
//	for (;;) {
//
//		/* See what poll() tells us about the userfaultfd */
//
//		struct pollfd pollfd;
//		int nready;
//
//		/* [H3: point 1]
//		 * Add uffd as the fd to poll. Wait for POLLIN event which means
//		 * the fd has data to read - corresponding with uffd_msg
//		 * structure becoming available due to access of registered
//		 * memory. Exit with error if poll returns error code. Else,
//		 * continue and print out if the POLLIN/POLLERR bits are set.
//		 */
//		pollfd.fd = uffd;
//		pollfd.events = POLLIN;
//		nready = poll(&pollfd, 1, -1);
//		if (nready == -1)
//			errExit("poll");
//
//		printf("\nfault_handler_thread():\n");
//		printf("    poll() returns: nready = %d; "
//                       "POLLIN = %d; POLLERR = %d\n", nready,
//                       (pollfd.revents & POLLIN) != 0,
//                       (pollfd.revents & POLLERR) != 0);
//
//		/* [H4: point 1]
//		 * Read data from the userfaultfd. This data with be of the type
//		 * struct uffd_msg and will contain details such as the event,
//		 * the fault flags, address of fault, userfault file descriptor
//		 * of child process, old and new addresses of remapped area,
//		 * original map length, start and end addresses of removed
//		 * areas. Exit with fault if read returns -1. These are in a
//		 * union so depending on the fault event, we look at the data
//		 * with different representations.
//		 */
//		nread = read(uffd, &msg, sizeof(msg));
//		if (nread == 0) {
//			printf("EOF on userfaultfd!\n");
//			exit(EXIT_FAILURE);
//		}
//
//		if (nread == -1)
//			errExit("read");
//
//		/* [H5: point 1]
//		 * If the event is an event other than PAGEFAULT event, exit
//		 * with an error as we do not handle other faults. There were
//		 * multiple other faults added in 4.11.
//		 */
//		if (msg.event != UFFD_EVENT_PAGEFAULT) {
//			fprintf(stderr, "Unexpected event on userfaultfd\n");
//			exit(EXIT_FAILURE);
//		}
//
//		/* [H6: point 1]
//		 * In the case it IS a PAGEFAULT event, print out the flags and
//		 * the address.
//		 */
//		printf("    UFFD_EVENT_PAGEFAULT event: ");
//		printf("flags = %llx; ", msg.arg.pagefault.flags);
//		printf("address = %llx\n", msg.arg.pagefault.address);
//
//		/* [H7: point 1]
//		 * Fill the previously mapped page with 'A' + number of faults
//		 * mod 20 for up to page_size. Similar to what is done on the
//		 * man page example. This math here is just to increase the
//		 * character A->B->C up to a limit of A+20, then it rolls back
//		 * to A.
//		 */
//		memset(page, 'A' + fault_cnt % 20, page_size);
//		fault_cnt++;
//
//		/* [H8: point 1]
//		 * Copy the page we just set into the destination which is the
//		 * address of the pagefault. This is accomplished first by
//		 * filling in the uffdio_copy struct with the parameters such as
//		 * the source, destination (which is the address at which we
//		 * pagefaulted at in the other thread), length(size of a page in
//		 * bytes). Mode is set to 0. Copy is reserved for ioctl to use.
//		 * In copy destination, assuming page_size is 4096, 4096-1 will
//		 * make a bitmask of 15 bits. Inverting that makes 15 0's with
//		 * everything from the 16th bit and up as 1. Doing a bitwise and
//		 * with this will shave off (floor) the address to the lowest
//		 * page.
//		 */
//		uffdio_copy.src = (unsigned long) page;
//		uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address &
//			~(page_size - 1);
//		uffdio_copy.len = page_size;
//		uffdio_copy.mode = 0;
//		uffdio_copy.copy = 0;
//
//		/* [H9: point 1]
//		 * Run the ioctl call on the userfaultfd and pass it the
//		 * arguments required for the copy command.
//		 */
//		if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
//			errExit("ioctl-UFFDIO_COPY");
//
//		/* [H10: point 1]
//		 * Print out the return value of the uffdio_copy command.
//		 */
//		printf("        (uffdio_copy.copy returned %lld)\n",
//                       uffdio_copy.copy);
//	}
//}

int serve_new_conn(int ask)
{
	int ret;
	char command[INPUT_CMD_LEN];
	/* Prompt User for mmap memory */
	printf("How many pages to mmap?");
	fgets(command, INPUT_CMD_LEN, stdin);


	return ret;
}

static void* setup_server(void* arg)
{
	char* argv = (char*) arg;
	/* Socket related variables */
	int sk, port, ret;
	int ask;
	struct sockaddr_in addr;
	port = atoi(argv[1]);

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(port);

	ret = bind(sk, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		errExit("Server bind failed");
	}

	printf("Waiting for connections\n");

	ask = accept(sk, NULL, NULL);
	if (ask < 0) {
		errExit("Server accept failed");
	}

	/* We've paired, no longer any need for sk */
	close(sk);
	ret = serve_new_conn(ask);

	return NULL;
}

static void* try_connect_client(void* arg)
{


	return NULL;
}
int
main(int argc, char *argv[])
{
	long uffd;          /* userfaultfd file descriptor */
	char *addr;         /* Start of region handled by userfaultfd */
	unsigned long len;  /* Length of region handled by userfaultfd */
	struct uffdio_api uffdio_api;
	struct uffdio_register uffdio_register;

	/* Create client first and try to connect. If other server doesn't
	 * exist, then we are the first node. Else, we are the second node. */


	/* Server thread related */
	int server_thread_return;
	pthread_t server_thread;

	if (argc != 4) {
		fprintf(stderr, "Usage: %s my_port remote_ip remote_port\n",
			argv[0]);
		exit(EXIT_FAILURE);
	}

	server_thread_return = pthread_create(&server_thread, NULL,
					      setup_server,
					      (void *) argv);
	if (server_thread_return != 0) {
		errno = server_thread_return;
		errExit("pthread_create");
	}
	page_size = sysconf(_SC_PAGE_SIZE);
	len = strtoul(argv[1], NULL, 0) * page_size;

//	uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
//	if (uffd == -1)
//		errExit("userfaultfd");
//
//	uffdio_api.api = UFFD_API;
//	uffdio_api.features = 0;
//	if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
//		errExit("ioctl-UFFDIO_API");

	addr = mmap(NULL, len, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED)
		errExit("mmap");

	printf("Address returned by mmap() = %p\n", addr);

//	/* [M6: point 1]
//	 * Register a memory range handled by the userfault fd and send it to
//	 * the userfaultfd object through ioctl. Exit with error if we fail the
//	 * ioctl. Take note of UFFDIO_REGISTER_MODE_MISSING. We only fire if
//	 * the pages are missing.
//	 */
//	uffdio_register.range.start = (unsigned long) addr;
//	uffdio_register.range.len = len;
//	uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
//	if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
//		errExit("ioctl-UFFDIO_REGISTER");
//
//	/* [M7: point 1]
//	 * Create new userspace thread to handle the fault handler. Link it to
//	 * the fault_handler_thread function and pass in pointer to the
//	 * userfaultfd object. Exit if error.
//	 */
//	s = pthread_create(&thr, NULL, fault_handler_thread, (void *) uffd);
//	if (s != 0) {
//		errno = s;
//		errExit("pthread_create");
//	}
//
	exit(EXIT_SUCCESS);
}
