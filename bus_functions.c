#include <sys/socket.h>
#include <linux/types.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <stdbool.h>

#include "bus_functions.h"
#include "userfault_handler.h"
#include "msi_statemachine.h"

extern struct msi_page pages[];
extern unsigned long g_pages_mapped;
pthread_mutex_t bus_lock = PTHREAD_MUTEX_INITIALIZER;

static void set_pages_in_use(unsigned long num)
{
	unsigned long i;
	for (i = 0; i < num; ++i)
	{
		pages[i].in_use = true;
	}
	g_pages_mapped = num;
}

void bus_thread_cleanup_handler(void* arg)
{
	/* Close out the sockets so we don't have loose ends */
	int sk = *(int*)arg;
	/* Ensure it's not stdin/out/err */
	printf("Cleanup handler called: %d\n", sk);
	if (sk >= 2)
		close(sk);
}

void* bus_thread_handler(void* arg)
{
	int rd;
	struct msi_message msg;
	struct bus_thread_args* bus_args = arg;

	if (!bus_args)
		errExit("Null Pointer");

	/* In case of thread cancellation, execute this handler */
	pthread_cleanup_push(bus_thread_cleanup_handler, &bus_args->fd);

	/* Main Event Loop for the bus*/
	for(;;) {
		rd = read(bus_args->fd, &msg, sizeof(msg));
		if (rd < 0)
			errExit("Read Error");
		switch(msg.message_type){
			case DISCONNECT:
				close(bus_args->fd);
				return NULL;
			case INVALID_STATE_READ:
				//printf("INVALID_STATE_READ_MSG_RECEIVED\n");
				msi_handle_page_request(bus_args->fd, &msg);
			break;
			case INVALIDATE:
				//printf("INVALIDATE_RECEIVED\n");
				msi_handle_page_invalidate(bus_args->fd, &msg);
			break;
			case PAGE_REPLY:
				//printf("PAGE_REPLY_RECEIVED\n");
			//if (*(msg.payload.page_data) != (int)0){
				//printf("payload page data: %s\n",
			//	       msg.payload.page_data);
			//}
			msi_handle_page_reply(bus_args->fd, &msg);
			break;
			case INVALIDATE_ACK:
				//printf("INVALIDATE_ACK_RECEIVED\n");
			break;
			default:
				printf("Unhandled bus request, %d\n",
				       msg.message_type);
			break;
		}
	}

	/* Cleanup pop 0 argument means we don't execute the handler in normal
	 * exit, which is true since we will never exit here anyway*/
	pthread_cleanup_pop(0);
	return NULL;
}

int setup_server(int port, struct bus_thread_args* arg_output, struct mmap_args*
		 mmap_output)
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
	unsigned long num_pages;

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
	printf("Connection established with client\n");

	/* Prompt User for mmap memory */
	printf("How many pages to mmap?: ");
	if (!fgets(command, INPUT_CMD_LEN, stdin)){
		errExit("fgets error");
	}

	page_size = sysconf(_SC_PAGE_SIZE);
	num_pages = strtoul(command, NULL, 0);
	len =  num_pages * page_size;
	if (len < 0)
		errExit("strtoul_server_setup");

	mmap_ptr = mmap(NULL, len, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mmap_ptr == MAP_FAILED)
		errExit("mmap");

	printf("Local mmap: Addr: %p, Length: %d\n"
	       ,mmap_ptr, len);

	set_pages_in_use(num_pages);

	/* Populate Message fields before sending */
	msg.message_type = CONNECTION_ESTABLISHED;
	msg.payload.memory_pair.address = (uint64_t)mmap_ptr;
	msg.payload.memory_pair.size = len;
	write_ret = write(ask, &msg , sizeof(msg));
	if (write_ret <= 0) {
		errExit("Server initial write error");
	}

	/* Output mmap details so it can be handled in the userfaultfd */
	mmap_output->memory_address = mmap_ptr;
	mmap_output->len = (uint64_t)len;

	/* Populate argument fields for worker thread */
	arg_output->fd = ask;
	arg_output->memory_address = (uint64_t)mmap_ptr;
	arg_output->len = len;

	/* We've paired, no longer any need for sk */
	close(sk);

	return ask;
}

int try_connect_client(int port, char* ip_string, struct
			      bus_thread_args* arg_output, struct mmap_args*
			      mmap_output)
{
	int sk = 0;
	int err = 0;
	struct sockaddr_in addr;
	int rd;
	struct msi_message msg;

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

	/* Initial pairing read to establish memory region */
	printf("Awaiting pairing request\n");
	rd = read(sk, &msg, sizeof(msg));
	if (rd < 0)
		errExit("Read Error");
	if (msg.message_type == CONNECTION_ESTABLISHED) {
		printf("Pairing Request Received: Addr: 0x%lx, Length: %lu\n"
		       ,msg.payload.memory_pair.address,
		       msg.payload.memory_pair.size);
	}
	set_pages_in_use(msg.payload.memory_pair.size/sysconf(_SC_PAGE_SIZE));
	/* Output mmap details so it can be handled in the userfaultfd */
	mmap_output->memory_address = (void*)msg.payload.memory_pair.address;
	mmap_output->len = msg.payload.memory_pair.size;
	/* Output the socket fd */
	arg_output->fd = sk;
	/* Return the socket if we successfully connect to it*/
	return sk;

out_close_socket:
	close(sk);
out_socket_err:
	return -1;
}
