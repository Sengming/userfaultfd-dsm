#ifndef __MESSAGES_H__
#define __MESSAGES_H__

enum msi_message_type
{
	CONNECTION_ESTABLISHED = 0,
	DISCONNECT,
	INVALID_STATE_READ,
	PAGE_REPLY,
	TOTAL_MESSAGES
};

struct memory_pair
{
	uint64_t address;
	uint64_t size;
};

struct command_ack
{
	int err;
};

union message_payload
{
	struct memory_pair memory_pair;
	struct command_ack command_ack;
};

struct msi_message
{
	enum msi_message_type message_type;
	union message_payload payload;
};
















#endif
