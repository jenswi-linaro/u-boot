/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2018 Linaro Limited
 */

#ifndef __TEE_H
#define __TEE_H

#include <common.h>
#include <dm.h>

#define TEE_UUID_LEN		16

#define TEE_GEN_CAP_GP          BIT(0)	/* GlobalPlatform compliant TEE */
#define TEE_GEN_CAP_REG_MEM     BIT(1)	/* Supports registering shared memory */

#define TEE_SHM_REGISTER	BIT(0)
#define TEE_SHM_SEC_REGISTER	BIT(1)
#define TEE_SHM_ALLOC		BIT(2)

#define TEE_PARAM_ATTR_TYPE_NONE		0	/* parameter not used */
#define TEE_PARAM_ATTR_TYPE_VALUE_INPUT		1
#define TEE_PARAM_ATTR_TYPE_VALUE_OUTPUT	2
#define TEE_PARAM_ATTR_TYPE_VALUE_INOUT		3	/* input and output */
#define TEE_PARAM_ATTR_TYPE_MEMREF_INPUT	5
#define TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT	6
#define TEE_PARAM_ATTR_TYPE_MEMREF_INOUT	7	/* input and output */
#define TEE_PARAM_ATTR_TYPE_MASK		0xff
#define TEE_PARAM_ATTR_META			0x100
#define TEE_PARAM_ATTR_MASK			(TEE_PARAM_ATTR_TYPE_MASK | \
						 TEE_PARAM_ATTR_META)

/*
 * Some Global Platform error codes which has a meaning if the
 * TEE_GEN_CAP_GP bit is returned by the driver.
 */
#define TEE_SUCCESS			0x00000000
#define TEE_ERROR_GENERIC		0xffff0000
#define TEE_ERROR_BAD_PARAMETERS	0xffff0006
#define TEE_ERROR_ITEM_NOT_FOUND	0xffff0008
#define TEE_ERROR_NOT_IMPLEMENTED	0xffff0009
#define TEE_ERROR_NOT_SUPPORTED		0xffff000a
#define TEE_ERROR_COMMUNICATION		0xffff000e
#define TEE_ERROR_OUT_OF_MEMORY		0xffff000c
#define TEE_ERROR_TARGET_DEAD		0xffff3024

#define TEE_ORIGIN_COMMS		0x00000002

struct tee_driver_ops;

struct tee_shm {
	struct udevice *dev;
	struct list_head link;
	void *addr;
	ulong size;
	u32 flags;
};

struct tee_param_memref {
	ulong shm_offs;
	ulong size;
	struct tee_shm *shm;
};

struct tee_param_value {
	u64 a;
	u64 b;
	u64 c;
};

struct tee_param {
	u64 attr;
	union {
		struct tee_param_memref memref;
		struct tee_param_value value;
	} u;
};

struct tee_open_session_arg {
	u8 uuid[TEE_UUID_LEN];
	u8 clnt_uuid[TEE_UUID_LEN];
	u32 clnt_login;
	u32 session;
	u32 ret;
	u32 ret_origin;
};

struct tee_invoke_arg {
	u32 func;
	u32 session;
	u32 ret;
	u32 ret_origin;
};

struct tee_version_data {
	u32 gen_caps;
};

struct tee_driver_ops {
	void (*get_version)(struct udevice *dev, struct tee_version_data *vers);
	int (*open_session)(struct udevice *dev,
			    struct tee_open_session_arg *arg, ulong num_param,
			    struct tee_param *param);
	int (*close_session)(struct udevice *dev, u32 session);
	int (*invoke_func)(struct udevice *dev, struct tee_invoke_arg *arg,
			   ulong num_param, struct tee_param *param);
	int (*shm_register)(struct udevice *dev, struct tee_shm *shm);
	int (*shm_unregister)(struct udevice *dev, struct tee_shm *shm);
};

struct tee_shm *__tee_shm_add(struct udevice *dev, ulong align, void *addr,
			      ulong size, u32 flags);
struct tee_shm *tee_shm_alloc(struct udevice *dev, ulong size, u32 flags);
struct tee_shm *tee_shm_register(struct udevice *dev, void *addr,
				 ulong length, u32 flags);
void tee_shm_free(struct tee_shm *shm);
bool tee_shm_is_registered(struct tee_shm *shm, struct udevice *dev);

struct udevice *tee_find_device(struct udevice *start,
				int (*match)(struct tee_version_data *vers,
					     const void *data),
				const void *data,
				struct tee_version_data *vers);

void tee_get_version(struct udevice *dev, struct tee_version_data *vers);
int tee_open_session(struct udevice *dev, struct tee_open_session_arg *arg,
		     ulong num_param, struct tee_param *param);

int tee_close_session(struct udevice *dev, u32 session);

int tee_invoke_func(struct udevice *dev, struct tee_invoke_arg *arg,
		    ulong num_param, struct tee_param *param);

#endif /*__TEE_H*/
