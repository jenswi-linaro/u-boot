/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <common.h>
#include <log.h>
#include <tee.h>
#include <mmc.h>

#include "optee_msg.h"
#include "optee_private.h"

/*
 * Request and response definitions must be in sync with the secure side
 */

/* Request */
struct rpmb_req {
	u16 cmd;
#define RPMB_CMD_DATA_REQ      0x00
#define RPMB_CMD_GET_DEV_INFO  0x01
	u16 dev_id;
	u16 block_count;
	/* Optional data frames (rpmb_data_frame) follow */
};
#define RPMB_REQ_DATA(req) ((void *)((struct rpmb_req *)(req) + 1))

/* Response to device info request */
struct rpmb_dev_info {
	u8 cid[16];
	u8 rpmb_size_mult;	/* EXT CSD-slice 168: RPMB Size */
	u8 rel_wr_sec_c;	/* EXT CSD-slice 222: Reliable Write Sector */
				/*                    Count */
	u8 ret_code;
#define RPMB_CMD_GET_DEV_INFO_RET_OK     0x00
#define RPMB_CMD_GET_DEV_INFO_RET_ERROR  0x01
};

/*
 * This structure is shared with OP-TEE and the MMC ioctl layer.
 * It is the "data frame for RPMB access" defined by JEDEC, minus the
 * start and stop bits.
 */
struct rpmb_data_frame {
	u8 stuff_bytes[196];
	u8 key_mac[32];
	u8 data[256];
	u8 nonce[16];
	u32 write_counter;
	u16 address;
	u16 block_count;
	u16 op_result;
#define RPMB_RESULT_OK				0x00
#define RPMB_RESULT_GENERAL_FAILURE		0x01
#define RPMB_RESULT_AUTH_FAILURE		0x02
#define RPMB_RESULT_ADDRESS_FAILURE		0x04
	u16 msg_type;
#define RPMB_MSG_TYPE_REQ_AUTH_KEY_PROGRAM		0x0001
#define RPMB_MSG_TYPE_REQ_WRITE_COUNTER_VAL_READ	0x0002
#define RPMB_MSG_TYPE_REQ_AUTH_DATA_WRITE		0x0003
#define RPMB_MSG_TYPE_REQ_AUTH_DATA_READ		0x0004
#define RPMB_MSG_TYPE_REQ_RESULT_READ			0x0005
#define RPMB_MSG_TYPE_RESP_AUTH_KEY_PROGRAM		0x0100
#define RPMB_MSG_TYPE_RESP_WRITE_COUNTER_VAL_READ	0x0200
#define RPMB_MSG_TYPE_RESP_AUTH_DATA_WRITE		0x0300
#define RPMB_MSG_TYPE_RESP_AUTH_DATA_READ		0x0400
};

static void release_mmc(struct optee_private *priv)
{
	int rc;

	if (!priv->rpmb_mmc)
		return;

	rc = blk_select_hwpart_devnum(IF_TYPE_MMC, priv->rpmb_dev_id,
				      priv->rpmb_original_part);
	if (rc)
		debug("%s: blk_select_hwpart_devnum() failed: %d\n",
		      __func__, rc);

	priv->rpmb_mmc = NULL;
}

static struct mmc *get_mmc(struct optee_private *priv, int dev_id)
{
	struct mmc *mmc;
	int rc;

	if (priv->rpmb_mmc && priv->rpmb_dev_id == dev_id)
		return priv->rpmb_mmc;

	release_mmc(priv);

	mmc = find_mmc_device(dev_id);
	if (!mmc) {
		debug("Cannot find RPMB device\n");
		return NULL;
	}
	if (!(mmc->version & MMC_VERSION_MMC)) {
		debug("Device id %d is not an eMMC device\n", dev_id);
		return NULL;
	}
	if (mmc->version < MMC_VERSION_4_41) {
		debug("Device id %d: RPMB not supported before version 4.41\n",
			dev_id);
		return NULL;
	}


#ifdef CONFIG_BLK
	priv->rpmb_original_part = mmc_get_blk_desc(mmc)->hwpart;
#else
	priv->rpmb_original_part = mmc->block_dev.hwpart;
#endif

	rc = blk_select_hwpart_devnum(IF_TYPE_MMC, dev_id, MMC_PART_RPMB);
	if (rc) {
		debug("Device id %d: cannot select RPMB partition: %d\n",
		      dev_id, rc);
		return NULL;
	}

	priv->rpmb_mmc = mmc;
	priv->rpmb_dev_id = dev_id;
	return mmc;
}

static int send_cmd(struct mmc *mmc, struct mmc_cmd *cmd, struct mmc_data *data)
{
#if CONFIG_IS_ENABLED(DM_MMC)
	return dm_mmc_send_cmd(mmc, cmd, data);
#else
	return mmc->cfg->ops->send_cmd(mmc, cmd, data);
#endif
}

static int send_set_blockcount(struct mmc *mmc, uint n, bool is_rel_write)
{
	struct mmc_cmd cmd = {
		.cmdidx = MMC_CMD_SET_BLOCK_COUNT,
		.resp_type = MMC_RSP_R1,
		.cmdarg = n & 0x0000FFFF,
	};

	if (is_rel_write)
		cmd.cmdarg |= BIT(31);

	return send_cmd(mmc, &cmd, NULL);
}

static int send_data_write(struct mmc *mmc, const struct rpmb_data_frame *frm,
			   ulong num_frm)
{
	struct mmc_cmd cmd = {
		.cmdidx = MMC_CMD_WRITE_MULTIPLE_BLOCK,
		.resp_type = MMC_RSP_R1b,
	};
	struct mmc_data data = {
		.src = (const void *)frm,
		.blocks = num_frm,
		.blocksize = sizeof(*frm),
		.flags = MMC_DATA_WRITE,
	};

	return send_cmd(mmc, &cmd, &data);
}

static int send_data_read(struct mmc *mmc, struct rpmb_data_frame *frm,
			  ulong num_frm)
{
	struct mmc_cmd cmd = {
		.cmdidx = MMC_CMD_READ_MULTIPLE_BLOCK,
		.resp_type = MMC_RSP_R1,
	};
	struct mmc_data data = {
		.dest = (void *)frm,
		.blocks = num_frm,
		.blocksize = sizeof(*frm),
		.flags = MMC_DATA_READ,
	};

	return send_cmd(mmc, &cmd, &data);
}

static int rpmb_status(struct mmc *mmc, struct rpmb_data_frame *frm)
{
	int rc;

	rc = send_set_blockcount(mmc, 1, false);
	if (rc)
		return rc;

	memset(frm, 0, sizeof(*frm));
	frm->msg_type = cpu_to_be16(RPMB_MSG_TYPE_REQ_RESULT_READ);
	rc = send_data_write(mmc, frm, 1);
	if (rc)
		return rc;

	rc = send_set_blockcount(mmc, 1, false);
	if (rc)
		return rc;

	return send_data_read(mmc, frm, 1);
}

static u32 rpmb_auth_data_write(struct mmc *mmc,
				const struct rpmb_data_frame *req,
				ulong req_nfrm, struct rpmb_data_frame *rsp,
				ulong rsp_nfrm)
{
	if (send_set_blockcount(mmc, req_nfrm, true))
		return TEE_ERROR_GENERIC;

	if (send_data_write(mmc, req, req_nfrm))
		return TEE_ERROR_GENERIC;

	if (rpmb_status(mmc, rsp))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static u32 rpmb_auth_data_read(struct mmc *mmc,
			       const struct rpmb_data_frame *req,
			       ulong req_nfrm, struct rpmb_data_frame *rsp,
			       ulong rsp_nfrm)
{
	if (send_set_blockcount(mmc, 1, false))
		return TEE_ERROR_GENERIC;

	if (send_data_write(mmc, req, 1))
		return TEE_ERROR_GENERIC;

	if (send_set_blockcount(mmc, 1, false))
		return TEE_ERROR_GENERIC;

	if (send_data_read(mmc, rsp, rsp_nfrm))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static u32 rpmb_data_req(struct mmc *mmc, struct rpmb_data_frame *req_frm,
			 ulong req_nfrm, struct rpmb_data_frame *rsp_frm,
			 ulong rsp_nfrm)
{
	ulong n;

	for (n = 1; n < req_nfrm; n++) {
		if (req_frm[n].msg_type != req_frm->msg_type) {
			debug("All request frames shall be of the same type\n");
			return TEE_ERROR_BAD_PARAMETERS;
		}
	}

	debug("Req: %zu frame(s) of type 0x%04x\n",
	     req_nfrm, be16_to_cpu(req_frm->msg_type));
	debug("Rsp: %zu frame(s)\n", rsp_nfrm);

	switch(be16_to_cpu(req_frm->msg_type)) {
	case RPMB_MSG_TYPE_REQ_AUTH_KEY_PROGRAM:
		if (req_nfrm != 1)
			return TEE_ERROR_BAD_PARAMETERS;
		/*FALLTHROUGH*/
	case RPMB_MSG_TYPE_REQ_AUTH_DATA_WRITE:
		if (rsp_nfrm != 1 || !req_nfrm)
			return TEE_ERROR_BAD_PARAMETERS;
		return rpmb_auth_data_write(mmc, req_frm, req_nfrm, rsp_frm,
					    rsp_nfrm);

	case RPMB_MSG_TYPE_REQ_WRITE_COUNTER_VAL_READ:
		if (rsp_nfrm != 1)
			return TEE_ERROR_BAD_PARAMETERS;
		/*FALLTHROUGH*/
	case RPMB_MSG_TYPE_REQ_AUTH_DATA_READ:
		if (!rsp_nfrm || req_nfrm != 1)
			return TEE_ERROR_BAD_PARAMETERS;
		return rpmb_auth_data_read(mmc, req_frm, req_nfrm, rsp_frm,
					   rsp_nfrm);
	default:
		debug("Unsupported message type: %d\n",
		      be16_to_cpu(req_frm->msg_type));
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

static u32 rpmb_get_dev_info(u16 dev_id, struct rpmb_dev_info *info)
{
	struct mmc *mmc = find_mmc_device(dev_id);

	if (!mmc)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (!mmc->ext_csd)
		return TEE_ERROR_GENERIC;

	memcpy(info->cid, mmc->cid, sizeof(info->cid));
	info->rel_wr_sec_c = mmc->ext_csd[222];
	info->rpmb_size_mult = mmc->ext_csd[168];
	info->ret_code = RPMB_CMD_GET_DEV_INFO_RET_OK;

	return TEE_SUCCESS;
}

/*
 * req is one struct rpmb_req followed by one or more struct rpmb_data_frame
 * rsp is either one struct rpmb_dev_info or one or more struct rpmb_data_frame
 */
static u32 rpmb_process_request(struct optee_private *priv, void *req,
				ulong req_size, void *rsp, ulong rsp_size)
{
	struct rpmb_req *sreq = req;
	struct mmc *mmc;
	ulong req_nfrm;
	ulong rsp_nfrm;

	if (req_size < sizeof(*sreq))
		return TEE_ERROR_BAD_PARAMETERS;


	switch (sreq->cmd) {
	case RPMB_CMD_DATA_REQ:
		mmc = get_mmc(priv, sreq->dev_id);
		if (!mmc)
			return TEE_ERROR_ITEM_NOT_FOUND;
		req_nfrm = (req_size - sizeof(struct rpmb_req)) / 512;
		rsp_nfrm = rsp_size / 512;
		return rpmb_data_req(mmc, RPMB_REQ_DATA(req), req_nfrm, rsp,
				     rsp_nfrm);

	case RPMB_CMD_GET_DEV_INFO:
		if (req_size != sizeof(struct rpmb_req) ||
		    rsp_size != sizeof(struct rpmb_dev_info)) {
			debug("Invalid req/rsp size\n");
			return TEE_ERROR_BAD_PARAMETERS;
		}
		return rpmb_get_dev_info(sreq->dev_id, rsp);

	default:
		debug("Unsupported RPMB command: %d\n", sreq->cmd);
		return TEE_ERROR_BAD_PARAMETERS;
	}

}

void optee_suppl_cmd_rpmb(struct udevice *dev, struct optee_msg_arg *arg)
{
	struct tee_shm *req_shm;
	struct tee_shm *rsp_shm;
	void *req_buf;
	void *rsp_buf;
	ulong req_size;
	ulong rsp_size;

	if (arg->num_params == 2 ||
	    arg->params[0].attr != OPTEE_MSG_ATTR_TYPE_RMEM_INPUT ||
	    arg->params[1].attr != OPTEE_MSG_ATTR_TYPE_RMEM_OUTPUT) {
		arg->ret = TEE_ERROR_BAD_PARAMETERS;
		return;
	}

	req_shm = (struct tee_shm *)(ulong)arg->params[0].u.rmem.shm_ref;
	req_buf = (u8 *)req_shm->addr + arg->params[0].u.rmem.offs;
	req_size = arg->params[0].u.rmem.size;

	rsp_shm = (struct tee_shm *)(ulong)arg->params[1].u.rmem.shm_ref;
	rsp_buf = (u8 *)rsp_shm->addr + arg->params[1].u.rmem.offs;
	rsp_size = arg->params[1].u.rmem.size;


	arg->ret = rpmb_process_request(dev_get_priv(dev), req_buf, req_size,
					rsp_buf, rsp_size);
}

void optee_suppl_rpmb_release(struct udevice *dev)
{
	release_mmc(dev_get_priv(dev));
}
