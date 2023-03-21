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
#include <linux/fs.h>   // file_operations
#include <linux/string.h>
#include <linux/slab.h>

#include "aesdchar.h"
int aesd_major = 0; // use dynamic major
int aesd_minor = 0;

MODULE_AUTHOR("Harsh Beriwal"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    struct aesd_dev *a_dev;
    PDEBUG("open");

    a_dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = a_dev;
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    struct aesd_dev *a_dev;
    PDEBUG("release");
    
    a_dev = container_of(inode ->i_cdev, struct aesd_dev,cdev);
    (void)a_dev;
    //filp->private_data = NULL;
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                  loff_t *f_pos)
{
    struct aesd_buffer_entry *element;
    struct aesd_dev *a_dev;
    ssize_t retval = 0;
    int buffer_count = 0;
    size_t offset;
    
    PDEBUG("read %zu bytes with offset %lld", count, *f_pos);

    a_dev = (struct aesd_dev*)filp->private_data;

    if (mutex_lock_interruptible(&a_dev->lock)!=0) {
	PDEBUG(KERN_ERR "Couldn't acquire Mutex\n");
	 mutex_unlock(&a_dev->lock);
	 return retval;
    }

    element = aesd_circular_buffer_find_entry_offset_for_fpos(&a_dev->circularBuffer, *f_pos, &offset);
    if(element==NULL) {
    	 mutex_unlock(&a_dev->lock);
	 return retval;
    }

    if ((element->size - offset) < count)  {
        *f_pos = *f_pos + (element->size - offset);
        buffer_count = element->size - offset;
    } else  {
        *f_pos = *f_pos + count;
        buffer_count = count;
    }

    if (copy_to_user(buf, element->buffptr+offset, buffer_count)) 
    {
	retval = -EFAULT;
	mutex_unlock(&a_dev->lock);
	return retval;
    }

    retval = buffer_count;

    mutex_unlock(&a_dev->lock);

    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                   loff_t *f_pos)
{
    ssize_t retval = 0;
    int bytes_to_send = 0, index =0; 
    int entries = 0, total_bytes = 0; 
    char *element;
    const char *freed_buff;
    struct aesd_buffer_entry w_buffer;
    struct aesd_dev *a_dev = filp->private_data;

    PDEBUG("write %zu bytes with offset %lld", count, *f_pos);
    
    if (mutex_lock_interruptible(&a_dev->lock)!=0) {
	PDEBUG(KERN_ERR "Couldn't acquire Mutex\n");
	return -EFAULT;
    }
    element = (char *)kmalloc(count, GFP_KERNEL);
    if (element == NULL)  {
        retval = -ENOMEM;
        mutex_unlock(&a_dev->lock);
  	return retval;
    }
    if (copy_from_user(element, buf, count))  {
        retval = -EFAULT;
	mutex_unlock(&a_dev->lock);
  	return retval;
    }
    for (index = 0; index < count; index++) {
        if (element[index] == '\n') {
            bytes_to_send = 1; 
            entries = index+1; 
            break;
        }
    }

    if (a_dev->buf_len == 0) {
        a_dev->buff = (char *)kmalloc(count, GFP_KERNEL);
        if (a_dev->buff == NULL) 
        {
            retval = -ENOMEM;
            kfree(element);
	    mutex_unlock(&a_dev->lock);
  	    return retval;
        }
        memcpy(a_dev->buff, element, count);
        a_dev->buf_len += count;
    } 
    else 
    {
        if (bytes_to_send)
            total_bytes = entries;
        else
            total_bytes = count;

        a_dev->buff = (char *)krealloc(a_dev->buff, a_dev->buf_len + total_bytes, GFP_KERNEL);
        if (a_dev->buff == NULL) 
        {
            retval = -ENOMEM;
            kfree(element);
	    mutex_unlock(&a_dev->lock);
  	    return retval;
        }
      
        memcpy(a_dev->buff + a_dev->buf_len, element, total_bytes);
        a_dev->buf_len += total_bytes;        
    }
 
    if (bytes_to_send) 
    {
        w_buffer.buffptr = a_dev->buff;
        w_buffer.size = a_dev->buf_len;
        freed_buff = aesd_circular_buffer_add_entry(&a_dev->circularBuffer, &w_buffer);
    
        if (freed_buff != NULL)
            kfree(freed_buff);
        a_dev->buf_len = 0;
    } 
    retval = count; 
    kfree(element);
    mutex_unlock(&a_dev->lock);
    return retval;
}

struct file_operations aesd_fops = {
    .owner = THIS_MODULE,
    .read = aesd_read,
    .write = aesd_write,
    .open = aesd_open,
    .release = aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *a_dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&a_dev->cdev, &aesd_fops);
    a_dev->cdev.owner = THIS_MODULE;
    a_dev->cdev.ops = &aesd_fops;
    err = cdev_add(&a_dev->cdev, devno, 1);
    if (err)
    {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}

int aesd_init_module(void)
{
    dev_t a_dev = 0;
    int result;
    result = alloc_chrdev_region(&a_dev, aesd_minor, 1,
                                 "aesdchar");
    aesd_major = MAJOR(a_dev);
    if (result < 0)
    {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device, 0, sizeof(struct aesd_dev));

    /**
     * TODO: initialize the AESD specific portion of the device
     */
    mutex_init(&aesd_device.lock);

    result = aesd_setup_cdev(&aesd_device);

    if (result)
    {
        unregister_chrdev_region(a_dev, 1);
    }
    return result;
}

void aesd_cleanup_module(void)
{
    int count = 0;
    struct aesd_buffer_entry *element;
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     */

    AESD_CIRCULAR_BUFFER_FOREACH(element, &aesd_device.circularBuffer, count)
    {
        if (element->buffptr != NULL)
        {
            kfree(element->buffptr);
            element->size = 0;
        }
    }

    mutex_destroy(&aesd_device.lock);

    unregister_chrdev_region(devno, 1);
}

module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
