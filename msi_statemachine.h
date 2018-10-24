#ifndef __MSI_STATEMACHINE_H__
#define __MSI_STATEMACHINE_H__
#include "messages.h"

void msi_request_page(int sk, char* page, void* fault_addr, unsigned int rw);
void msi_handle_page_request(int sk, struct msi_message* in_msg);
void msi_handle_page_invalidate (int sk, struct msi_message* in_msg);
struct msi_page* find_msi_page(void* fault_addr);
//void msi_handle_invalidate_ack(int sk, struct msi_message* in_msg);
void msi_handle_page_reply(int sk, struct msi_message* in_msg);

#endif
