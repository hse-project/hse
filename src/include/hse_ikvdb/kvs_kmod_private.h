/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef KVS_KMOD_PRIVATE_H
#define KVS_KMOD_PRIVATE_H

#include <linux/device.h>
#include <linux/semaphore.h>
#include <linux/cdev.h>

#define KVS_MODULE_NAME "kvs"

struct kvs_dev {
    struct cdev      cdev;
    struct device *  device;
    dev_t            devno;
    struct semaphore sem;
};

int
kvs_kmod_open(struct inode *inode, struct file *file);

int
kvs_kmod_release(struct inode *inode, struct file *file);

long
kvs_kmod_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

#endif
