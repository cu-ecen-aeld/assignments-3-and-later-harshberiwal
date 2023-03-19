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
#include <linux/fs.h> // file_operations
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
    struct aesd_dev *in_dev = container_of(inode ->i_cdev, struct aesd_dev,cdev);
    filp->private_data = in_dev; 
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    struct aesd_dev *in_dev = container_of(inode ->i_cdev, struct aesd_dev,cdev);
    (void)in_dev;
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t ret = 0, offset = 0;
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);

    struct aesd_dev* in_dev = filp->private_data;
	struct aesd_buffer_entry *entry = NULL;

    entry = in_dev->element;

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

    return ret;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
	const char* lBuffptr = NULL;

    if (mutex_lock_interruptible(&in_dev->lock) != 0)
    {
        printk(KERN_INFO "Failed to aquire Mutex.\n");
        mutex_unlock(&in_dev->lock);
	    return ret;
    }

	// remove this
	struct aesd_dev* in_dev = filp->private_data;

    if (in_dev->element->size == 0) {
        in_dev->element->buffptr = (char *)kzalloc(count, GFP_KERNEL);
    }
    else {
        in_dev->element->buffptr = (char *)krealloc(in_dev->element->buffptr,
                                              in_dev->element->size + count, GFP_KERNEL);
    }

	if (dev->element->buffptr != NULL) {
		retval = copy_from_user((void *)dev->element->buffptr + dev->element->size, buf, count);
		retval = count - retval;
        in_dev->element->size += retval;

        if (in_dev->element->buffptr[(in_dev->element->size - 1)] == '\n')
        {
            lBuffptr = aesd_circular_buffer_add_entry(&in_dev->circularBuffer, &in_dev->element);
            if (lBuffptr != NULL) {
                kfree(lBuffptr);
			}
			in_dev->element->size = 0;
            in_dev->element->buffptr = NULL;
            
        }
    }
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
    aesd_device.element = kmalloc(sizeof(struct aesd_buffer_entry), GFP_KERNEL);
	aesd_circular_buffer_init(&aesd_device.circularBuffer);

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    struct aesd_buffer_entry *entry = NULL;
    dev_t devno = MKDEV(aesd_major, aesd_minor);
    int count=0;
    //S
    AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.circularBuffer, count) 
	{
		if(entry->buffptr != NULL)
		{
			kfree(entry->buffptr);
			entry->size = 0;
		}
	}

    if (aesd_device.element != NULL)
    {
		kfree(aesd_device.element);
	}

    cdev_del(&aesd_device.cdev);
    mutex_destroy(&aesd_device.lock);
    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
