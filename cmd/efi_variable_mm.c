// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2019 Linaro Ltd. <sughosh.ganu@linaro.org>
 *
 */

#include <common.h>
#include <command.h>
#include <errno.h>
#ifdef CONFIG_OPTEE
#include <tee.h>
#endif

#include <efi.h>
#include <efi_api.h>
#include <efi_loader.h>
#include <linux/arm-smccc.h>
#include <malloc.h>
#include <mm_communication.h>
#include <mm_variable.h>

#define ARM_MM_COMMUNICATE_AARCH64	0xC4000041UL
#define NS_S_MM_COMM_BUF		0xC0000000UL

static efi_uintn_t max_var_size = 0x200;
static uint8_t *var_buffer;

#ifdef CONFIG_OPTEE

/*
 * Interface to the pseudo TA, which provides a communication channel with
 * the Standalone MM SP (StMM) running at S-EL0.
 */

#define PTA_STMM_UUID { 0xed32d533, 0x99e6, 0x4209, {\
			0x9c, 0xc0, 0x2d, 0x72, 0xcd, 0xd9, 0x98, 0xa7 } }

/*
 * Pass a buffer to Standalone MM SP
 *
 * [in/out]     memref[0]:	EFI Communication buffer
 * [out]	value[1].a:	EFI return code
 */
#define PTA_STMM_COMMUNICATE	0



struct mm_connection {
	struct udevice *tee;
	u32 session;
};

static struct mm_connection *get_connection(void)
{
	static struct mm_connection conn = { NULL, 0 };
	struct udevice *tee = NULL;

	while (!conn.tee) {
		const struct tee_optee_ta_uuid uuid = PTA_STMM_UUID;
		struct tee_open_session_arg arg;
		int rc;

		tee = tee_find_device(tee, NULL, NULL, NULL);
		if (!tee)
			return NULL;

		memset(&arg, 0, sizeof(arg));
		tee_optee_ta_uuid_to_octets(arg.uuid, &uuid);
		rc = tee_open_session(tee, &arg, 0, NULL);
		if (!rc) {
			conn.tee = tee;
			conn.session = arg.session;
		}
	}

	return &conn;
}

static efi_status_t efi_mm_communicate(void **comm_buf, ulong *dsize)
{
	ulong buf_size;
	efi_status_t ret;
	mm_communicate_header_t *mm_hdr;
	struct mm_connection *conn;
	struct tee_invoke_arg arg;
	struct tee_param param[2];
	struct tee_shm *shm = NULL;
	int rc;

	if (!comm_buf || !dsize)
		return EFI_INVALID_PARAMETER;

	mm_hdr = *comm_buf;
	buf_size = mm_hdr->message_len + sizeof(efi_guid_t) + sizeof(size_t);

	if (*dsize != buf_size)
		return EFI_INVALID_PARAMETER;

	conn = get_connection();
	if (!conn)
		return EFI_UNSUPPORTED;

	if (tee_shm_register(conn->tee, *comm_buf, buf_size, 0, &shm))
		return EFI_UNSUPPORTED;

	memset(&arg, 0, sizeof(arg));
	arg.func = PTA_STMM_COMMUNICATE;
	arg.session = conn->session;

	memset(param, 0, sizeof(param));
	param[0].attr = TEE_PARAM_ATTR_TYPE_MEMREF_INOUT;
	param[0].u.memref.size = buf_size;
	param[0].u.memref.shm = shm;
	param[1].attr = TEE_PARAM_ATTR_TYPE_VALUE_OUTPUT;

	rc = tee_invoke_func(conn->tee, &arg, 2, param);
	tee_shm_free(shm);
	if (rc)
		return EFI_INVALID_PARAMETER;

	switch (param[1].u.value.a) {
	case MM_RET_SUCCESS:
		ret = EFI_SUCCESS;
		break;

	case MM_RET_INVALID_PARAMS:
		ret = EFI_INVALID_PARAMETER;
		break;

	case MM_RET_DENIED:
		ret = EFI_ACCESS_DENIED;
		break;

	case MM_RET_NO_MEMORY:
		ret = EFI_OUT_OF_RESOURCES;
		break;

	default:
		ret = EFI_ACCESS_DENIED;
	}

	return ret;
}
#else
static efi_status_t efi_mm_communicate(void **comm_buf, ulong *dsize)
{
	ulong buf_size;
	ulong smc_fid;
	ulong mm_comm_buf;
	efi_status_t ret;
	struct arm_smccc_res res;
	mm_communicate_header_t *mm_hdr;

	if (!comm_buf || !dsize)
		return EFI_INVALID_PARAMETER;

	mm_hdr = *comm_buf;
	buf_size = mm_hdr->message_len + sizeof(efi_guid_t) + sizeof(size_t);

	if (*dsize != buf_size)
		return EFI_INVALID_PARAMETER;

	smc_fid = ARM_MM_COMMUNICATE_AARCH64;
	mm_comm_buf = NS_S_MM_COMM_BUF;
	memcpy((void *)mm_comm_buf, *comm_buf, buf_size);
	arm_smccc_smc(smc_fid, 0, (ulong)mm_comm_buf, 0, 0, 0, 0, 0, &res);

	switch(res.a0) {
	case MM_RET_SUCCESS:
		memcpy(*comm_buf, (const void *)mm_comm_buf, buf_size);
		ret = EFI_SUCCESS;
		break;

	case MM_RET_INVALID_PARAMS:
		ret = EFI_INVALID_PARAMETER;
		break;

	case MM_RET_DENIED:
		ret = EFI_ACCESS_DENIED;
		break;

	case MM_RET_NO_MEMORY:
		ret = EFI_OUT_OF_RESOURCES;
		break;

	default:
		ret = EFI_ACCESS_DENIED;
	}

	return ret;
}
#endif

static efi_status_t mm_communicate(efi_uintn_t dsize)
{
	efi_status_t ret;
	mm_communicate_header_t *mm_hdr;
	mm_variable_communicate_t *mm_var_hdr;

	dsize += MM_COMMUNICATE_HEADER_SIZE + MM_VARIABLE_COMMUNICATE_SIZE;
	mm_hdr = (mm_communicate_header_t *)var_buffer;
	mm_var_hdr = (mm_variable_communicate_t *)mm_hdr->data;

	ret = efi_mm_communicate((void **)&var_buffer, &dsize);
	if (ret != EFI_SUCCESS) {
		printf("efi_mm_communicate failed!\n");
		return ret;
	}

	return mm_var_hdr->ret_status;
}

static efi_status_t init_mm_comm_hdr(void **dptr, efi_uintn_t comm_size,
				     efi_uintn_t func)
{
	efi_guid_t mm_var_guid = EFI_MM_VARIABLE_GUID;
	mm_communicate_header_t *mm_hdr;
	mm_variable_communicate_t *mm_var_hdr;

	/*
	 * Check if the all the headers put together with
	 * the payload exceeds the max variable size
	 */
	if (comm_size + MM_COMMUNICATE_HEADER_SIZE +
	    MM_VARIABLE_COMMUNICATE_SIZE > max_var_size)
		return EFI_INVALID_PARAMETER;

	mm_hdr = (mm_communicate_header_t *)var_buffer;
	guidcpy(&mm_hdr->header_guid, &mm_var_guid);
	mm_hdr->message_len = comm_size + MM_VARIABLE_COMMUNICATE_SIZE;

	mm_var_hdr = (mm_variable_communicate_t *)mm_hdr->data;
	mm_var_hdr->function = func;
	if (dptr != NULL)
		*dptr = mm_var_hdr->data;

	return EFI_SUCCESS;
}

static efi_status_t get_var_mm(u16 *var_name, efi_guid_t *guid, uint32_t *attr,
			       efi_uintn_t *datasize, void *data)
{
	ulong dsize;
	ulong comm_size;
	efi_status_t ret;
	ulong var_name_len;
	ulong var_access_hdr_size;
	mm_variable_access *var_access;

	if (!var_name || !guid || !datasize)
		return EFI_INVALID_PARAMETER;

	var_access = NULL;
	dsize = *datasize;
	var_name_len = u16_strsize(var_name);
	var_access_hdr_size = MM_VARIABLE_ACCESS_HEADER_SIZE;

	if (var_name_len > max_var_size - var_access_hdr_size)
		return EFI_INVALID_PARAMETER;

	if (dsize > max_var_size - var_access_hdr_size - var_name_len)
		dsize = max_var_size - var_access_hdr_size - var_name_len;

	comm_size = var_access_hdr_size + var_name_len + dsize;

	/* Initialise the headers before calling MM_COMMUNICATE */
	ret = init_mm_comm_hdr((void **)&var_access, comm_size,
			       MM_VARIABLE_FUNCTION_GET_VARIABLE);

	if (!var_access)
		return EFI_OUT_OF_RESOURCES;

	guidcpy(&var_access->guid, guid);
	var_access->data_size = dsize;
	var_access->name_size = var_name_len;
	var_access->attr = *attr;

	u16_strcpy(var_access->name, var_name);

	ret = mm_communicate(comm_size);

	if (ret == EFI_SUCCESS || ret == EFI_BUFFER_TOO_SMALL)
		*datasize = var_access->data_size;

	if (attr != NULL)
		*attr = var_access->attr;

	if (ret != EFI_SUCCESS)
		goto done;

	if (data != NULL) {
		memcpy(data, (uint8_t *)var_access->name +
		       var_access->name_size, var_access->data_size);
	} else {
		return EFI_INVALID_PARAMETER;
	}

done:
	return ret;
}

static int do_get_efi_variable(cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[])
{
	u8 var_name[15];
	u16 var_name16[15], *ptr;
	efi_status_t ret;
	efi_guid_t efi_global_variable_guid = EFI_GLOBAL_VARIABLE_GUID;
	uint32_t attr;
	efi_uintn_t datasize;
	u16 *data;

	datasize = 0;
	data = NULL;
	attr = 0;

	var_buffer = malloc(max_var_size);

	if (!var_buffer) {
		printf("Unable to allocate variable buffer\n");
		return CMD_RET_FAILURE;
	}

	strncpy((char *)var_name, "Timeout", strlen("Timeout") + 1);
	ptr = var_name16;
	utf8_utf16_strncpy(&ptr, (const char *)var_name, 15);

#if 0
	/* Get the variable data size first */
	ret = get_var_mm(var_name16, &efi_global_variable_guid, &attr,
			 &datasize, data);

	if (ret != EFI_BUFFER_TOO_SMALL)
		return CMD_RET_FAILURE;
#endif

	/*
	 * Ideally, the size of the uefi variable would be obtained
	 * through a call to StandaloneMm. But since we are using a
	 * hacked version of StMm, just assume a datasize of 20 bytes.
	 */
	data = malloc(20);
	datasize = 20;
	if (!data) {
		printf("Unable to allocate memory for the variable data\n");
		free(var_buffer);
		return CMD_RET_FAILURE;
	}

	ret = get_var_mm(var_name16, &efi_global_variable_guid, &attr,
			 &datasize, data);

	if (ret != EFI_SUCCESS) {
		ret = CMD_RET_FAILURE;
		goto fail;
	}

	printf("Timeout received from GetVariable => %ls\n", data);
	ret = CMD_RET_SUCCESS;
fail:
	free(var_buffer);
	free(data);
	return ret;
}

U_BOOT_CMD(
	get_var_mm,	1,		1,	do_get_efi_variable,
	"Get a variable via MM_COMMUNICATE uefi protocol",
	""
);
