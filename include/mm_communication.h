#if !defined _MM_COMMUNICATION_H_
#define _MM_COMMUNICATION_H_

typedef struct {
	efi_guid_t header_guid;
	size_t     message_len;
	uint8_t    data[1];
} mm_communicate_header_t;

#define MM_COMMUNICATE_HEADER_SIZE	(offsetof(mm_communicate_header_t, data))

#define MM_RET_SUCCESS			 0
#define MM_RET_INVALID_PARAMS		-2
#define MM_RET_DENIED			-3
#define MM_RET_NO_MEMORY		-4

#endif /* _MM_COMMUNICATION_H_*/
