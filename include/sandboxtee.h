/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (C) 2018 Linaro Limited
 */

#ifndef __SANDBOXTEE_H
#define __SANDBOXTEE_H

struct sandbox_tee_state {
	u32 session;
	int num_shms;
	void *ta;
};

#endif /*__SANDBOXTEE_H*/
