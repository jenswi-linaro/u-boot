/*
 * Copyright (c) 2018, Linaro Limited
 *
 * SPDX-License-Identifier:	BSD-2-Clause
 */

#include <dm.h>
#include <common.h>
#include <tee.h>
#include <log.h>
#include <stdio.h>
#include <stdlib.h>
#include <tee_client_api.h>

static TEEC_Result pre_process_tmpref(TEEC_Context *ctx, uint32_t param_type,
				      TEEC_TempMemoryReference *tmpref,
				      struct tee_param *param,
				      struct tee_shm **shm)
{
	switch (param_type) {
	case TEEC_MEMREF_TEMP_INPUT:
		param->attr = TEE_PARAM_ATTR_TYPE_MEMREF_INPUT;
		break;
	case TEEC_MEMREF_TEMP_OUTPUT:
		param->attr = TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT;
		break;
	case TEEC_MEMREF_TEMP_INOUT:
		param->attr = TEE_PARAM_ATTR_TYPE_MEMREF_INOUT;
		break;
	default:
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	*shm = tee_shm_register(ctx->dev, tmpref->buffer, tmpref->size, 0);
	if (!*shm)
		return TEEC_ERROR_OUT_OF_MEMORY;

	param->u.memref.shm_offs = 0;
	param->u.memref.size = tmpref->size;
	param->u.memref.shm = *shm;
	return TEEC_SUCCESS;
}

static TEEC_Result pre_process_whole(TEEC_RegisteredMemoryReference *memref,
				     struct tee_param *param)
{
	switch (memref->parent->flags & (TEEC_MEM_INPUT | TEEC_MEM_OUTPUT)) {
	case TEEC_MEM_INPUT | TEEC_MEM_OUTPUT:
		param->attr = TEE_PARAM_ATTR_TYPE_MEMREF_INOUT;
		break;
	case TEEC_MEM_INPUT:
		param->attr = TEE_PARAM_ATTR_TYPE_MEMREF_INPUT;
		break;
	case TEEC_MEM_OUTPUT:
		param->attr = TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT;
		break;
	default:
		return TEEC_ERROR_BAD_PARAMETERS;
	}
	param->u.memref.shm_offs = 0;
	param->u.memref.size = memref->parent->size;
	param->u.memref.shm = memref->parent->shm;
	return TEEC_SUCCESS;
}

static TEEC_Result pre_process_partial(uint32_t param_type,
				       TEEC_RegisteredMemoryReference *memref,
				       struct tee_param *param)
{
	switch (param_type) {
	case TEEC_MEMREF_PARTIAL_INPUT:
		param->attr = TEE_PARAM_ATTR_TYPE_MEMREF_INPUT;
		break;
	case TEEC_MEMREF_PARTIAL_OUTPUT:
		param->attr = TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT;
		break;
	case TEEC_MEMREF_PARTIAL_INOUT:
		param->attr = TEE_PARAM_ATTR_TYPE_MEMREF_INOUT;
		break;
	default:
		return TEEC_ERROR_BAD_PARAMETERS;
	}
	param->u.memref.shm_offs = memref->offset;
	param->u.memref.size = memref->size;
	param->u.memref.shm = memref->parent->shm;
	return TEEC_SUCCESS;
}

static TEEC_Result
pre_process_operation(TEEC_Context *ctx, TEEC_Operation *op,
		      struct tee_param *params, struct tee_shm **shm)
{
	TEEC_Result res;
	ulong n;

	if (!op) {
		memset(params, 0, sizeof(struct tee_param) *
				  TEEC_CONFIG_PAYLOAD_REF_COUNT);
		return TEEC_SUCCESS;
	}

	for (n = 0; n < TEEC_CONFIG_PAYLOAD_REF_COUNT; n++) {
		uint32_t param_type;

		param_type = TEEC_PARAM_TYPE_GET(op->paramTypes, n);
		switch (param_type) {
		case TEEC_NONE:
			params[n].attr = param_type;
			break;
		case TEEC_VALUE_INPUT:
		case TEEC_VALUE_OUTPUT:
		case TEEC_VALUE_INOUT:
			params[n].attr = param_type;
			params[n].u.value.a = op->params[n].value.a;
			params[n].u.value.b = op->params[n].value.b;
			break;
		case TEEC_MEMREF_TEMP_INPUT:
		case TEEC_MEMREF_TEMP_OUTPUT:
		case TEEC_MEMREF_TEMP_INOUT:
			res = pre_process_tmpref(ctx, param_type,
						 &op->params[n].tmpref,
						 params + n, shm + n);
			if (res)
				return res;
			break;
		case TEEC_MEMREF_WHOLE:
			res = pre_process_whole(&op->params[n].memref,
						params + n);
			if (res)
				return res;
			break;
		case TEEC_MEMREF_PARTIAL_INPUT:
		case TEEC_MEMREF_PARTIAL_OUTPUT:
		case TEEC_MEMREF_PARTIAL_INOUT:
			res = pre_process_partial(param_type,
						  &op->params[n].memref,
						  params + n);
			if (res)
				return res;
			break;
		default:
			return TEEC_ERROR_BAD_PARAMETERS;
		}
	}

	return TEEC_SUCCESS;
}

static void post_process_tmpref(uint32_t param_type,
				TEEC_TempMemoryReference *tmpref,
				struct tee_param *param, struct tee_shm **shm)
{
	tee_shm_free(*shm);
	*shm = NULL;

	if (param_type != TEEC_MEMREF_TEMP_INPUT)
		tmpref->size = param->u.memref.size;
}

static void
post_process_operation(TEEC_Operation *op, struct tee_param *params,
		       struct tee_shm **shm)
{
	ulong n;

	if (!op)
		return;

	for (n = 0; n < TEEC_CONFIG_PAYLOAD_REF_COUNT; n++) {
		uint32_t param_type;

		param_type = TEEC_PARAM_TYPE_GET(op->paramTypes, n);
		switch (param_type) {
		case TEEC_VALUE_INPUT:
			break;
		case TEEC_VALUE_OUTPUT:
		case TEEC_VALUE_INOUT:
			op->params[n].value.a = params[n].u.value.a;
			op->params[n].value.b = params[n].u.value.b;
			break;
		case TEEC_MEMREF_TEMP_INPUT:
		case TEEC_MEMREF_TEMP_OUTPUT:
		case TEEC_MEMREF_TEMP_INOUT:
			post_process_tmpref(param_type, &op->params[n].tmpref,
					    params + n, shm + n);
			break;
		default:
			break;
		}
	}
}

static void uuid_to_octets(u8 d[TEE_UUID_LEN], const TEEC_UUID *s)
{
	d[0] = s->timeLow >> 24;
	d[1] = s->timeLow >> 16;
	d[2] = s->timeLow >> 8;
	d[3] = s->timeLow;
	d[4] = s->timeMid >> 8;
	d[5] = s->timeMid;
	d[6] = s->timeHiAndVersion >> 8;
	d[7] = s->timeHiAndVersion;
	memcpy(d + 8, s->clockSeqAndNode, sizeof(s->clockSeqAndNode));
}

TEEC_Result TEEC_OpenSession(TEEC_Context *ctx, TEEC_Session *session,
			const TEEC_UUID *destination,
			uint32_t connection_method, const void *connection_data,
			TEEC_Operation *op, uint32_t *error_origin)
{
	struct tee_open_session_arg arg;
	struct tee_param params[TEEC_CONFIG_PAYLOAD_REF_COUNT];
	struct tee_shm *tmp_shm[TEEC_CONFIG_PAYLOAD_REF_COUNT] = { NULL };
	int rc;
	TEEC_Result res;

	(void)&connection_data;
	if (!ctx || !session) {
		*error_origin = TEEC_ORIGIN_API;
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	memset(&arg, 0, sizeof(arg));
	memset(params, 0, sizeof(params));
	uuid_to_octets(arg.uuid, destination);
	arg.clnt_login = connection_method;

	res = pre_process_operation(ctx, op, params, tmp_shm);
	if (res != TEEC_SUCCESS) {
		*error_origin = TEEC_ORIGIN_API;
		goto out;
	}

	rc = tee_open_session(ctx->dev, &arg, TEEC_CONFIG_PAYLOAD_REF_COUNT,
			      params);
	if (rc) {
		*error_origin = TEEC_ORIGIN_COMMS;
		res = TEEC_ERROR_GENERIC;
		goto out;
	}

	*error_origin = arg.ret_origin;
	res = arg.ret;
	if (!res) {
		session->ctx = ctx;
		session->session_id = arg.session;
	}
out:
	post_process_operation(op, params, tmp_shm);

	return res;
}

void TEEC_CloseSession(TEEC_Session *session)
{
	int rc;

	if (!session)
		return;

	rc = tee_close_session(session->ctx->dev, session->session_id);
	if (rc)
		debug("Failed to close session 0x%x\n", session->session_id);
}

TEEC_Result TEEC_InvokeCommand(TEEC_Session *session, uint32_t cmd_id,
			       TEEC_Operation *op, uint32_t *error_origin)
{
	struct tee_invoke_arg arg;
	struct tee_param params[TEEC_CONFIG_PAYLOAD_REF_COUNT];
	struct tee_shm *tmp_shm[TEEC_CONFIG_PAYLOAD_REF_COUNT] = { NULL };
	int rc;
	TEEC_Result res;

	memset(&arg, 0, sizeof(arg));
	memset(params, 0, sizeof(params));
	arg.func = cmd_id;
	arg.session = session->session_id;

	res = pre_process_operation(session->ctx, op, params, tmp_shm);
	if (res != TEEC_SUCCESS) {
		*error_origin = TEEC_ORIGIN_API;
		goto out;
	}

	rc = tee_invoke_func(session->ctx->dev, &arg,
			     TEEC_CONFIG_PAYLOAD_REF_COUNT, params);
	if (rc) {
		*error_origin = TEEC_ORIGIN_COMMS;
		res = TEEC_ERROR_GENERIC;
		goto out;
	}
	*error_origin = arg.ret_origin;
	res = arg.ret;
out:
	post_process_operation(op, params, tmp_shm);

	return res;
}

void TEEC_RequestCancellation(TEEC_Operation *op)
{
	(void)&op;
}

TEEC_Result TEEC_RegisterSharedMemory(TEEC_Context *ctx, TEEC_SharedMemory *shm)
{
	size_t s = 8;
	if (!ctx || !shm || !shm->buffer)
		return TEEC_ERROR_BAD_PARAMETERS;

	if (!shm->flags || (shm->flags & ~(TEEC_MEM_INPUT | TEEC_MEM_OUTPUT)))
		return TEEC_ERROR_BAD_PARAMETERS;

	if (shm->size)
		s = shm->size;

	shm->shm = tee_shm_register(ctx->dev, shm->buffer, s, 0);
	if (!shm->shm)
		return TEEC_ERROR_OUT_OF_MEMORY;

	return TEEC_SUCCESS;
}

TEEC_Result TEEC_AllocateSharedMemory(TEEC_Context *ctx, TEEC_SharedMemory *shm)
{
	size_t s = 8;

	if (!ctx || !shm)
		return TEEC_ERROR_BAD_PARAMETERS;

	if (!shm->flags || (shm->flags & ~(TEEC_MEM_INPUT | TEEC_MEM_OUTPUT)))
		return TEEC_ERROR_BAD_PARAMETERS;

	if (shm->size)
		s = shm->size;

	shm->shm = tee_shm_alloc(ctx->dev, s, 0);
	if (!shm->shm)
		return TEEC_ERROR_OUT_OF_MEMORY;

	shm->buffer = shm->shm->addr;
	return TEEC_SUCCESS;
}

void TEEC_ReleaseSharedMemory(TEEC_SharedMemory *shm)
{
	tee_shm_free(shm->shm);
	shm->shm = NULL;
}

static int teec_match(struct tee_version_data *vers, const void *data)
{
	const u32 req_caps = TEE_GEN_CAP_GP | TEE_GEN_CAP_REG_MEM;

	if (data)
		return 0;

	return ((vers->gen_caps & req_caps) == req_caps);
}

TEEC_Result TEEC_InitializeContext(const char *name, TEEC_Context *ctx)
{
	if (!ctx)
		return TEEC_ERROR_BAD_PARAMETERS;

	ctx->dev = tee_find_device(NULL, teec_match, name, NULL);
	if (!ctx->dev)
		return TEEC_ERROR_ITEM_NOT_FOUND;

	return TEEC_SUCCESS;
}

void TEEC_FinalizeContext(TEEC_Context *ctx)
{
	(void)&ctx;
}
