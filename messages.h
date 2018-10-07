#ifndef __MESSAGES_H__
#define __MESSAGES_H__

enum msi_message_type
{
	CONNECTION_ESTABLISHED = 0,
	INVALID_STATE_READ,
	PAGE_REPLY,
	TOTAL_MESSAGES
};

union message_payload
{
	struct memory_pair
	{
		int address;
		int size;
	};
	struct command_ack
	{
		int err;
	};
};

struct msi_message
{
	enum msi_message_type;
	union message_payload payload;
};
















#endif
