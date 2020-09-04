#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include "msi_statemachine.h"
#include "messages.h"
#include "types.h"
#include "stdint.h"
#include "stdio.h"
#include <string.h>
#include <pthread.h>

extern struct msi_page pages[];
extern unsigned long g_pages_mapped;
extern pthread_mutex_t bus_lock;

int waiting_for_page_reply = 0;
pthread_cond_t page_reply_cond  = PTHREAD_COND_INITIALIZER;
char global_data_buffer[4096];

struct msi_page* find_msi_page(void* fault_addr)
{
	struct msi_page* page = NULL;
	uint64_t addr_val = (uint64_t)fault_addr;
	int iterator = 0;

	for (iterator = 0; iterator < g_pages_mapped; ++iterator){
		if ((uint64_t)pages[iterator].start_address+sysconf(_SC_PAGE_SIZE)
			 > addr_val){
			page = &pages[iterator];
			break;
		}
	}

	return page;
}

void msi_request_page(int sk, char* page, void* fault_addr, unsigned int rw)
{
	int write_ret;
	struct msi_message msg;
	pthread_mutex_lock(&bus_lock);
	struct msi_page* page_to_transition = find_msi_page(fault_addr);
	if (!page_to_transition){
		errExit("Unable to find page\n");
	}

	pthread_mutex_lock(&page_to_transition->mutex);

	/* If we are invalid, we need to get data from other node */
	/* Populate Message fields before sending */
	msg.message_type = INVALID_STATE_READ;
	msg.payload.request_page.address = (uint64_t)fault_addr;
	msg.payload.request_page.size = sysconf(_SC_PAGE_SIZE);
	write_ret = write(sk, &msg , sizeof(msg));
	if (write_ret <= 0) {
		goto out_bad;
	}

	/* Use condition variable to wait for bus thread to
	 * reply with page data*/
	memset(&global_data_buffer, 0, 4096);
	waiting_for_page_reply = 1;
	while(waiting_for_page_reply == 1)
		pthread_cond_wait(&page_reply_cond, &bus_lock);

	/* Wait for reply */
	memcpy(page, &global_data_buffer, sysconf(_SC_PAGE_SIZE));
	page_to_transition->tag = SHARED;
	goto out_good;


out_good:
	pthread_mutex_unlock(&bus_lock);
	pthread_mutex_unlock(&page_to_transition->mutex);
	return;
out_bad:
	pthread_mutex_unlock(&page_to_transition->mutex);
	errExit("request_page_failed");
}

void msi_handle_page_request(int sk, struct msi_message* in_msg)
{
	int write_ret;
	struct msi_message msg_out;

	/* Find the page we're concerned about */
	struct msi_page* page_to_transition =
		find_msi_page((void*)in_msg->payload.request_page.address);
	if (!page_to_transition){
		errExit("Unable to find page\n");
	}
	msg_out.message_type = PAGE_REPLY;

	/*If I'm invalid too, then I'll give you an empty page */
	if (page_to_transition->tag == INVALID) {
		memset(msg_out.payload.page_data, 0, sysconf(_SC_PAGE_SIZE));
	}
	else {
		/* Else I'll give you my local memory storage, won't trigger
		 * pagefault since it's already been edited anyway */
		memcpy(msg_out.payload.page_data, page_to_transition->start_address,
			sysconf(_SC_PAGE_SIZE));
	}
	pthread_mutex_lock(&page_to_transition->mutex);
	write_ret = write(sk, &msg_out, sizeof(msg_out));
	if (write_ret <= 0) {
		goto out_bad;
	}
				//printf("[%p]MODIFIED TO SHARED\n",
				//       page_to_transition->start_address);
	page_to_transition->tag = SHARED;
	goto out_good;
out_bad:
	pthread_mutex_unlock(&page_to_transition->mutex);
	errExit("handle_page_request_error");
out_good:
	pthread_mutex_unlock(&page_to_transition->mutex);
	return;
}

void msi_handle_page_invalidate (int sk, struct msi_message* in_msg)
{
	int write_ret;
	struct msi_message msg;

	/* Find the page we're concerned about */
	struct msi_page* page_to_transition =
		find_msi_page((void*)in_msg->payload.invalidate_page.address);
	if (!page_to_transition){
		errExit("Unable to find page\n");
	}

	pthread_mutex_lock(&page_to_transition->mutex);
	page_to_transition->tag = INVALID;
	if (madvise(page_to_transition->start_address, sysconf(_SC_PAGE_SIZE), MADV_DONTNEED)) {
		errExit("fail to madvise");
	}
				//printf("[%p]TO_INVALID\n",
				 //      page_to_transition->start_address);
	msg.message_type = INVALIDATE_ACK;
	/* Ignore payload for now until we add error handling */
	write_ret = write(sk, &msg, sizeof(msg));
	if (write_ret <= 0) {
		errExit("page_invalidate_failed");
	}
	pthread_mutex_unlock(&page_to_transition->mutex);
}

void msi_handle_page_reply(int sk, struct msi_message* in_msg)
{
	pthread_mutex_lock(&bus_lock);
	memcpy(&global_data_buffer, in_msg->payload.page_data,
	       sysconf(_SC_PAGE_SIZE));
	waiting_for_page_reply = 0;
	/* Signal condition variable that we are ready */
	pthread_cond_signal(&page_reply_cond);
	pthread_mutex_unlock(&bus_lock);
}

void msi_handle_invalidate_ack(int sk, struct msi_message* in_msg)
{
	/* Wait for reply, ack */
}
