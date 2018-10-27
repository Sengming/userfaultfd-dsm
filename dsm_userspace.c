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
#include <stdbool.h>

#include "messages.h"
#include "types.h"
#include "bus_functions.h"
#include "userfault_handler.h"

#define TOTAL_NUM_ARGS		(4)

char* msi_strings[NUM_TAGS] = {"INVALID", "MODIFIED", "SHARED"};

/* Global page array */
struct msi_page pages[MAX_PAGES];
unsigned long g_pages_mapped;

static void initialize_msi_pages()
{
	int i;
	for(i = 0; i < MAX_PAGES; ++i){
		pages[i].tag = INVALID;
		pthread_mutex_init(&pages[i].mutex, NULL);
		pages[i].in_use = false;
		pages[i].start_address = NULL;
	}
}

static void address_msi_pages(uint64_t mmap_addr, uint64_t phy_addr)
{
	int i;
	uint64_t page_addr = mmap_addr;
	int page_size = sysconf(_SC_PAGE_SIZE);
	for(i = 0; i < MAX_PAGES; ++i, page_addr+=page_size, phy_addr+=page_size){
		pages[i].start_address = (void*)page_addr;
		pages[i].physical_address = (void*)phy_addr;
	}
}

static void handle_write_command(int sk)
{
	char cmd_buffer[INPUT_CMD_LEN] = {0};
	char write_buffer[WRITE_BUF_LEN] = {0};
	unsigned long page_num;
	unsigned long iterator;
	struct msi_message msg;
	int write_ret;

	printf("\nWhat page would you like to write to? (0 to N-1 or i): ");
	if (!fgets(cmd_buffer, INPUT_CMD_LEN, stdin))
		errExit("fgets error");

	printf("\nWhat would you like to write?:\n");
	if (!fgets(write_buffer, WRITE_BUF_LEN, stdin))
		errExit("fgets error");

	page_num = strtoul(cmd_buffer, NULL, 0);
	if (!strncmp(cmd_buffer, "i", 1)){
		for (iterator = 0; iterator < g_pages_mapped; ++iterator) {
			memcpy(pages[iterator].start_address,write_buffer,
				strlen(write_buffer));
			pages[iterator].tag = MODIFIED;
			msg.message_type = INVALIDATE;
			msg.payload.invalidate_page.address =
				(uint64_t)pages[iterator].start_address;
			write_ret = write(sk, &msg, sizeof(msg));
			if (write_ret <= 0) {
				errExit("Bad write");
			}
		}
	}
	else if (page_num < g_pages_mapped) {
		//printf("\nCopying %s to address %p\n", write_buffer,
		//       pages[page_num].start_address);
		memcpy(pages[page_num].start_address, write_buffer,
		       strlen(write_buffer));
		pages[page_num].tag = MODIFIED;
		msg.message_type = INVALIDATE;
		msg.payload.invalidate_page.address =
			(uint64_t)pages[page_num].start_address;
		write_ret = write(sk, &msg, sizeof(msg));
		if (write_ret <= 0) {
			errExit("Bad write");
		}
	}
}

static void handle_read_command()
{
	char cmd_buffer[INPUT_CMD_LEN] = {0};
	unsigned long page_num;
	unsigned long iterator;
	char *probe;

	printf("\nWhat page would you like to read from? (0 to N-1 or i): ");
	if (!fgets(cmd_buffer, INPUT_CMD_LEN, stdin))
		errExit("fgets error");

	page_num = strtoul(cmd_buffer, NULL, 0);
	if (!strncmp(cmd_buffer, "i", 1)){
		for (iterator = 0; iterator < g_pages_mapped; ++iterator) {
			probe = (char*)pages[iterator].start_address;
			char c = *probe;
			if (*probe == (int)0){
				/* If the page has not been written to yet */
				printf("[*]Page %lu:\n\n", iterator);
			}
			else {
				/* String contained in page */
				printf("[*]Page %lu:\n%s\n", iterator, probe);
			}

		}
	}
	else if (page_num < g_pages_mapped) {
		probe = (char*)pages[page_num].start_address;
		char c = *probe;
		if (*probe == (int)0){
			printf("Read String: \n");
		}
		else {
			printf("Read String: %s\n", probe);
		}
	}
}

static void handle_msi_status_command()
{
	char cmd_buffer[INPUT_CMD_LEN] = {0};
	unsigned long page_num;
	unsigned long iterator;
	char *probe;

	printf("\nWhat page would you like to view status of? (0 to N-1 or i): ");
	if (!fgets(cmd_buffer, INPUT_CMD_LEN, stdin))
		errExit("fgets error");

	page_num = strtoul(cmd_buffer, NULL, 0);
	if (!strncmp(cmd_buffer, "i", 1)){
		for (iterator = 0; iterator < g_pages_mapped; ++iterator) {
			printf("[*]Page %lu: %s \n", iterator,
			       msi_strings[pages[iterator].tag]);
		}
	}
	else if (page_num < g_pages_mapped) {
		printf("[*]Page %lu: %s \n", page_num,
			       msi_strings[pages[page_num].tag]);
	}
}

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
	void* physical_address;
	int exit_write_ret;

	/* Message */
	struct msi_message msg;

	if (argc != TOTAL_NUM_ARGS) {
		fprintf(stderr, "Usage: %s my_port remote_ip remote_port\n",
			argv[0]);
		exit(EXIT_FAILURE);
	}

	initialize_msi_pages();

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
				 &physical_address,
				 shared_mapping.len, &userfaultfd_thread,
				 &fault_handler_thread, socket_fd);

	address_msi_pages((uint64_t)shared_mapping.memory_address,
			  (uint64_t)physical_address);

	/* Prompt User for Command */
	for(;;) {
		printf("\nWhat would you like to do? (r)ead/(w)rite/(v)iew msi/E(x)it?: ");
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
			handle_write_command(socket_fd);
		}
		else if (!strncmp(fgets_buffer, "r", 1)){
			handle_read_command();
		}
		else if (!strncmp(fgets_buffer, "v", 1)){
			handle_msi_status_command();
		}
	}

exit_success:
	printf("EXITING");
	exit(EXIT_SUCCESS);
}
