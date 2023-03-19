/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h>       // file_operations
#include <linux/slab.h>     // kzalloc & krealloc

#include "aesdchar.h"
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Harinarayanan Gajapathy");
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    struct aesd_dev *dev = NULL;

    PDEBUG("open\n");

    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = dev; /* for other methods */

    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release\n");

    filp->private_data = NULL;

    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    size_t entry_offset = 0;
    struct aesd_buffer_entry *entry = NULL;
    struct aesd_dev *dev = filp->private_data;

    PDEBUG("read %zu bytes with offset %lld\n", count, *f_pos);

    if (mutex_lock_interruptible(&dev->lock) != 0) {
        PDEBUG("failed to acquire mutex\n");
		return -ERESTARTSYS;
    }

    entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->cb, *f_pos, &entry_offset);
    if (entry != NULL) {
        retval = copy_to_user(buf, (entry->buffptr + entry_offset), (entry->size - entry_offset));
        retval = (entry->size - entry_offset) - retval;
        *f_pos += retval;
    }

    PDEBUG("aesd_read returns %ld\n", retval);

    mutex_unlock(&dev->lock);

    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    const char *rtnptr = NULL;
    struct aesd_dev *dev = filp->private_data;

    PDEBUG("write %zu bytes with offset %lld\n", count, *f_pos);

    if (mutex_lock_interruptible(&dev->lock) != 0) {
        PDEBUG("failed to acquire mutex\n");
		return -ERESTARTSYS;
    }

    if (dev->entry.size == 0) {
        dev->entry.buffptr = (char *) kzalloc(count, GFP_KERNEL);
    } else {
        dev->entry.buffptr = (char *) krealloc(dev->entry.buffptr, \
                                dev->entry.size + count, GFP_KERNEL);
    }

    if (dev->entry.buffptr == NULL) {
        PDEBUG("failed to allocate memory\n");
        retval = -ENOMEM;
    } else {
        /* copy_from_user - returns number of bytes that could not be copied.
        * On success, this will be zero. */
        retval = copy_from_user((void *) dev->entry.buffptr + dev->entry.size, buf, count);

        retval = count - retval;
        dev->entry.size += retval;
        PDEBUG("copied %ld bytes from userspace to kernel space, total size %ld\n", \
                    retval, dev->entry.size);

        if (dev->entry.buffptr[(dev->entry.size - 1)] == '\n') {
            rtnptr = aesd_circular_buffer_add_entry(&dev->cb, &dev->entry);
            if (rtnptr != NULL)
                kfree(rtnptr);

            dev->entry.buffptr = NULL;
            dev->entry.size = 0;
        }
    }

    mutex_unlock(&dev->lock);

    return retval;
}

struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add(&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }

    return err;
}

int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;

    PDEBUG("init_module\n");

    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    mutex_init(&aesd_device.lock);
    aesd_circular_buffer_init(&aesd_device.cb);

    result = aesd_setup_cdev(&aesd_device);
    if (result) {
        unregister_chrdev_region(dev, 1);
    }

    return result;
}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);
    struct aesd_buffer_entry *entry = NULL;
    int index = 0;

    PDEBUG("cleanup_module\n");

    AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.cb, index) {
        if (entry->buffptr != NULL) {
            PDEBUG("bufferptr - %s, size %ld\n", entry->buffptr, entry->size);
            kfree(entry->buffptr);
        }
    }

    cdev_del(&aesd_device.cdev);

    unregister_chrdev_region(devno, 1);
}

module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
