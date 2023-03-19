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
#include <linux/fs.h> 	    // file_operations
#include <linux/slab.h>    
#include "aesdchar.h"

int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Harsh Beriwal"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    //finding the aesd_dev data structure linked with the inode and assigning it to private_data
    struct aesd_dev *in_dev = NULL; 
    in_dev = container_of(inode ->i_cdev, struct aesd_dev,cdev);
    filp->private_data = in_dev; 
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    //struct aesd_dev *in_dev;
    filp ->private_data = NULL;
    //in_dev = container_of(inode ->i_cdev, struct aesd_dev,cdev);
    //(void)in_dev;
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t ret = 0, offset = 0;
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);

    struct aesd_dev *in_dev = NULL;
    in_dev = filp->private_data;
    struct aesd_buffer_entry *entry = NULL;

    //entry = in_dev->element;

    if (mutex_lock_interruptible(&in_dev->lock) != 0)
    {
        printk(KERN_INFO "Failed to aquire Mutex.\n");
        mutex_unlock(&in_dev->lock);
	    return ret;
    }

    entry = aesd_circular_buffer_find_entry_offset_for_fpos(&in_dev->circularBuffer, *f_pos, &offset);

    if(entry == NULL)
    {
        mutex_unlock(&in_dev->lock);
        return ret;
    }
    else {
        if(copy_to_user(buf, (entry->buffptr + offset), (entry->size - offset)) == 0) {
            ret = entry->size - offset;
        }
        else {
            mutex_unlock(&in_dev->lock);
	    return ret;
        }
    }
    *f_pos += entry->size - offset; 
    printk(KERN_INFO "New fpos %lld\n", *f_pos); 
    mutex_unlock(&in_dev -> lock); 
    return ret;
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

    if (dev->element.size == 0) {
        dev->element.buffptr = (char *) kzalloc(count, GFP_KERNEL);
    } else {
        dev->element.buffptr = (char *) krealloc(dev->element.buffptr, \
                                dev->element.size + count, GFP_KERNEL);
    }

    if (dev->element.buffptr == NULL) {
        PDEBUG("failed to allocate memory\n");
        retval = -ENOMEM;
    } else {
        /* copy_from_user - returns number of bytes that could not be copied.
        * On success, this will be zero. */
        retval = copy_from_user((void *) dev->element.buffptr + dev->element.size, buf, count);

        retval = count - retval;
        dev->element.size += retval;
        PDEBUG("copied %ld bytes from userspace to kernel space, total size %ld\n", \
                    retval, dev->element.size);

        if (dev->element.buffptr[(dev->element.size - 1)] == '\n') {
            rtnptr = aesd_circular_buffer_add_entry(&dev->circularBuffer, &dev->element);
            if (rtnptr != NULL)
                kfree(rtnptr);

            dev->element.buffptr = NULL;
            dev->element.size = 0;
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
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    /**
     * TODO: initialize the AESD specific portion of the device
     */
    //H&S
    mutex_init(&aesd_device.lock);
    //aesd_device.element = kmalloc(sizeof(struct aesd_buffer_entry), GFP_KERNEL);
    aesd_circular_buffer_init(&aesd_device.circularBuffer);

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);
    struct aesd_buffer_entry *element = NULL;
    int count=0;
    //S
    AESD_CIRCULAR_BUFFER_FOREACH(element, &aesd_device.circularBuffer, count) 
	{
		if(element->buffptr != NULL)
		{
			kfree(element->buffptr);
			//element->size = 0;
		}
	}

    cdev_del(&aesd_device.cdev);
    //mutex_destroy(&aesd_device.lock);
    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
