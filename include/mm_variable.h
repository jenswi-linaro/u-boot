#if !defined _MM_VARIABLE_H_
#define _MM_VARIABLE_H_

#include <part_efi.h>

typedef struct {
	efi_uintn_t    function;
	efi_status_t   ret_status;
	uint8_t        data[1];
} mm_variable_communicate_t;

#define MM_VARIABLE_COMMUNICATE_SIZE	(offsetof(mm_variable_communicate_t, data))

#define MM_VARIABLE_FUNCTION_GET_VARIABLE			1

#define MM_VARIABLE_FUNCTION_GET_NEXT_VARIABLE_NAME		2

#define MM_VARIABLE_FUNCTION_SET_VARIABLE			3

#define MM_VARIABLE_FUNCTION_QUERY_VARIABLE_INFO		4

#define MM_VARIABLE_FUNCTION_READY_TO_BOOT			5

#define MM_VARIABLE_FUNCTION_EXIT_BOOT_SERVICE			6

#define MM_VARIABLE_FUNCTION_GET_STATISTICS			7

#define MM_VARIABLE_FUNCTION_LOCK_VARIABLE			8

#define MM_VARIABLE_FUNCTION_VAR_CHECK_VARIABLE_PROPERTY_SET	9

#define MM_VARIABLE_FUNCTION_VAR_CHECK_VARIABLE_PROPERTY_GET	10

#define MM_VARIABLE_FUNCTION_GET_PAYLOAD_SIZE			11

typedef struct {
	efi_guid_t        guid;
	efi_uintn_t       data_size;
	efi_uintn_t       name_size;
	uint32_t          attr;
	u16               name[1];
} mm_variable_access;

#define MM_VARIABLE_ACCESS_HEADER_SIZE		(offsetof(mm_variable_access, name))

#endif /* _MM_VARIABLE_H_ */
