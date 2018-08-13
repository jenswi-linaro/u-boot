/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2018 Linaro Limited
 */

#ifndef __OPTEE_PRIVATE_H
#define __OPTEE_PRIVATE_H

#include <tee.h>
#include <log.h>

struct optee_private {
	struct mmc *rpmb_mmc;
	int rpmb_dev_id;
	char rpmb_original_part;
};

struct optee_msg_arg;

void optee_suppl_cmd(struct udevice *dev, struct tee_shm *shm_arg,
		     void **page_list);

#ifdef CONFIG_SUPPORT_EMMC_RPMB
void optee_suppl_cmd_rpmb(struct udevice *dev, struct optee_msg_arg *arg);
void optee_suppl_rpmb_release(struct udevice *dev);
#else
static inline void optee_suppl_cmd_rpmb(struct udevice *dev,
					struct optee_msg_arg *arg)
{
	debug("OPTEE_MSG_RPC_CMD_RPMB not implemented\n");
	arg->ret = TEE_ERROR_NOT_IMPLEMENTED;
}

static inline void optee_suppl_rpmb_release(struct udevice *dev)
{
}
#endif

void *optee_alloc_and_init_page_list(void *buf, ulong len, u64 *phys_buf_ptr);

#endif /*__OPTEE_PRIVATE_H*/
