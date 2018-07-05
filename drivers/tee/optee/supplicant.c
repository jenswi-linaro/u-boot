/*
 * Copyright (c) 2018, Linaro Limited
 *
 * SPDX-License-Identifier:	BSD-2-Clause
 */

#include <asm/semihosting.h>
#include <common.h>
#include <linux/types.h>
#include <log.h>
#include <tee.h>
#include <uuid.h>

#include "optee_msg.h"
#include "optee_msg_supplicant.h"
#include "optee_private.h"
#include "optee_smc.h"

#ifdef CONFIG_SEMIHOSTING
static int fname_from_uuid(char *fname, size_t fnlen, void *uuid_bin)
{
	char uuid_str[UUID_STR_LEN + 1];

	uuid_bin_to_str(uuid_bin, uuid_str, UUID_STR_FORMAT_STD);
	return snprintf(fname, fnlen, "%s.ta", uuid_str);
}

static u32 load_ta(void *uuid_bin, void *buf, size_t *len)
{
	u32 res;
	char fname[1024];
	long fd;
	long l;

	l = fname_from_uuid(fname, sizeof(fname), uuid_bin);
	if (l < 0 || l >= sizeof(fname))
		return TEE_ERROR_ITEM_NOT_FOUND;

	fd = smh_open(fname, "rb");
	if (fd < 0)
		return TEE_ERROR_ITEM_NOT_FOUND;

	l = smh_len_fd(fd);
	if (l <= 0) {
		res = TEE_ERROR_ITEM_NOT_FOUND;
		goto out;
	}

	if (l > *len) {
		*len = l;
		res = TEE_SUCCESS;
		goto out;
	}

	if (smh_read(fd, buf, l)) {
		res = TEE_ERROR_ITEM_NOT_FOUND;
		goto out;
	}

	*len = l;
	res = TEE_SUCCESS;
out:
	smh_close(fd);
	return res;
}

static void cmd_load_ta(struct optee_msg_arg *arg)
{
	struct tee_shm *shm;
	void *buf;
	size_t sz;
	void *uuid_bin;

	arg->ret_origin = TEE_ORIGIN_COMMS;

	if (arg->num_params != 2) {
		arg->ret = TEE_ERROR_BAD_PARAMETERS;
		return;
	}
	if (arg->params[0].attr != OPTEE_MSG_ATTR_TYPE_VALUE_INPUT) {
		arg->ret = TEE_ERROR_BAD_PARAMETERS;
		return;
	}

	uuid_bin = (void *)&arg->params[0].u.value;

	switch (arg->params[1].attr) {
	case OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT:
		sz = 0;
		arg->ret = load_ta(uuid_bin, NULL, &sz);
		arg->params[1].u.tmem.size = sz;
		break;
	case OPTEE_MSG_ATTR_TYPE_RMEM_OUTPUT:
		shm = (void *)(unsigned long)arg->params[1].u.rmem.shm_ref;
		sz = arg->params[1].u.rmem.size;
		buf = (u8 *)shm->addr + arg->params[1].u.rmem.offs;
		arg->ret = load_ta(uuid_bin, buf, &sz);
		arg->params[1].u.rmem.size = sz;
		break;
	default:
		arg->ret = TEE_ERROR_BAD_PARAMETERS;
	}
}
#else
static void cmd_load_ta(struct optee_msg_arg *arg)
{
	debug("OPTEE_MSG_RPC_CMD_LOAD_TA not supported\n");
	arg->ret_origin = TEE_ORIGIN_COMMS;
	arg->ret = TEE_ERROR_NOT_SUPPORTED;
}
#endif

static void cmd_shm_alloc(struct udevice *dev, struct optee_msg_arg *arg,
			  void **page_list)
{
	struct tee_shm *shm;
	void *pl;
	u64 ph_ptr;

	arg->ret_origin = TEE_ORIGIN_COMMS;

	if (arg->num_params != 1 ||
	    arg->params[0].attr != OPTEE_MSG_ATTR_TYPE_VALUE_INPUT) {
		arg->ret = TEE_ERROR_BAD_PARAMETERS;
		return;
	}

	shm = __tee_shm_add(dev, 0, NULL, arg->params[0].u.value.b,
			    TEE_SHM_REGISTER | TEE_SHM_ALLOC);
	if (!shm) {
		arg->ret = TEE_ERROR_OUT_OF_MEMORY;
		return;
	}

	pl = optee_alloc_and_init_page_list(shm->addr, shm->size, &ph_ptr);
	if (!pl) {
		arg->ret = TEE_ERROR_OUT_OF_MEMORY;
		tee_shm_free(shm);
		return;
	}

	*page_list = pl;
	arg->params[0].attr = OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT |
			      OPTEE_MSG_ATTR_NONCONTIG;
	arg->params[0].u.tmem.buf_ptr = ph_ptr;
	arg->params[0].u.tmem.size = shm->size;
	arg->params[0].u.tmem.shm_ref = (ulong)shm;
	arg->ret = TEE_SUCCESS;
}


static void cmd_shm_free(struct optee_msg_arg *arg)
{
	arg->ret_origin = TEE_ORIGIN_COMMS;

	if (arg->num_params != 1 ||
		arg->params[0].attr != OPTEE_MSG_ATTR_TYPE_VALUE_INPUT) {
		arg->ret = TEE_ERROR_BAD_PARAMETERS;
		return;
	}

	tee_shm_free((struct tee_shm *)(ulong)arg->params[0].u.value.b);
	arg->ret = TEE_SUCCESS;
}

void optee_suppl_cmd(struct udevice *dev, struct tee_shm *shm_arg,
		     void **page_list)
{
	struct optee_msg_arg *arg = shm_arg->addr;

	switch (arg->cmd) {
	case OPTEE_MSG_RPC_CMD_SHM_ALLOC:
		cmd_shm_alloc(dev, arg, page_list);
		break;
	case OPTEE_MSG_RPC_CMD_SHM_FREE:
		cmd_shm_free(arg);
		break;
	case OPTEE_MSG_RPC_CMD_LOAD_TA:
		cmd_load_ta(arg);
		break;
	case OPTEE_MSG_RPC_CMD_FS:
		debug("OPTEE_MSG_RPC_CMD_FS not implemented\n");
		arg->ret = TEE_ERROR_NOT_IMPLEMENTED;
		break;
	default:
		debug("Unknown RPC cmd 0x%x\n", arg->cmd);
		arg->ret = TEE_ERROR_NOT_IMPLEMENTED;
	}

	arg->ret_origin = TEE_ORIGIN_COMMS;
}
