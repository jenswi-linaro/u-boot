// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2019 Linaro Ltd. <sughosh.ganu@linaro.org>
 *
 */

#include <common.h>
#include <command.h>
#include <errno.h>
#include <malloc.h>

#include <linux/arm-smccc.h>

#define MM_COMMUNICATE				(0xC4000041ul)
#define MM_VERSION				(0x84000040ul)

static int do_mmver(cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[])
{
	struct arm_smccc_res res;
	unsigned int smc_fid;
	unsigned int major, minor;

	smc_fid = MM_VERSION;
	arm_smccc_smc(smc_fid, 0, 0, 0, 0, 0, 0, 0, &res);

	major = (res.a0 >> 16) & 0x7fff;
	minor = res.a0 & 0xffff;

	if (major == 1 && minor == 1) {
		printf("Got response to MM_COMMUNICATE from op-tee OS\n");
	} else {
		printf("Failed to get response to MM_COMMUNICATE from op-tee OS\n");
	}

	return 0;
}

U_BOOT_CMD(
	mm_version,	1,		1,	do_mmver,
	"Get MM version implemented in Secure world",
	""
);
