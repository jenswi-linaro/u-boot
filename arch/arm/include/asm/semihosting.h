/*
 * Copyright 2018 Linaro Limited
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#ifndef __ASM_SEMIHOSTING_H
#define __ASM_SEMIHOSTING_H

#include <linux/types.h>

long smh_open(const char *fname, char *modestr);
long smh_read(long fd, void *memp, size_t len);
long smh_close(long fd);
long smh_len_fd(long fd);

#endif /*__ASM_SEMIHOSTING_H*/
