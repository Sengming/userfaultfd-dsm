#ifndef __MESSAGES_H__
#define __MESSAGES_H__
#include <stdint.h>

enum msi_message_type
{
	CONNECTION_ESTABLISHED = 0,
	DISCONNECT,
	INVALID_STATE_READ,
	PAGE_REPLY,
	INVALIDATE,
	INVALIDATE_ACK,
	TOTAL_MESSAGES
};
/* Different types of payloads defined here*/
struct memory_pair
{
	uint64_t address;
	uint64_t size;
};

struct command_ack
{
	int err;
};

struct request_page
{
	uint64_t address;
	uint64_t size;
};

struct invalidate_page
{
	uint64_t address;
};
/* Message payload and its structure */
union message_payload
{
	struct memory_pair memory_pair;
	struct command_ack command_ack;
	struct request_page request_page;
	struct invalidate_page invalidate_page;
	char page_data[4096];
};

struct msi_message
{
	enum msi_message_type message_type;
	union message_payload payload;
};

//struct msi_page_data_payload
//{
//	enum msi_message_type message_type;
//	char payload[4096];
//};













#endif
