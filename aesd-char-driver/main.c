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
#include <linux/slab.h>
#include <linux/string.h>
#include "aesd-circular-buffer.h"
#include "aesdchar.h"
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Harsh Beriwal"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
	/**
	 * TODO: handle open
	 */
	struct aesd_dev* aDev = container_of(inode->i_cdev, struct aesd_dev, cdev);
	PDEBUG("open");
	filp->private_data = aDev;
	return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
	/**
	 * TODO: handle release
	 */
	struct aesd_dev* aDev = container_of(inode->i_cdev, struct aesd_dev, cdev);
	(void)aDev;
	PDEBUG("release");
	return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
	//char* lBuffptr = NULL;
	ssize_t i = 0, retval = 0, temp = 0, bytesToRead = 0;
	/**
	 * TODO: handle read
	 */
	struct aesd_dev* aDev = NULL;
	struct aesd_buffer_entry *entry = NULL;
	
	printk(KERN_INFO "read %zu bytes with offset %lld",count,*f_pos);

	aDev = (struct aesd_dev*)filp->private_data;
	entry = aDev->element;
	{
		if (mutex_lock_interruptible(&aDev->lock) != 0)
		{
			printk(KERN_INFO "Mutex failed to aquire.\n");
			goto end;
		}
		
		entry = aesd_circular_buffer_find_entry_offset_for_fpos(&aDev->circularBuffer, *f_pos, &temp);


		if(entry == NULL)
		{
			//continue;
			goto end;
		}

		printk(KERN_INFO " %ld bytes, string: %s\n", entry->size, entry->buffptr);
		//else if(entry->size > count

		{
			bytesToRead = entry->size - temp;
			if(copy_to_user(buf, entry->buffptr + temp, bytesToRead) == 0)
			{

				retval = bytesToRead;
			}
			else
			{
				goto end;
			}
		}
		{

		}
	}

	//printk(KERN_INFO "New fpos %lld\n", *f_pos);
	//if((entry->size - temp) != entry->size)
	*f_pos += bytesToRead;

	printk(KERN_INFO "New fpos %lld\n", *f_pos);
end:
	mutex_unlock(&aDev->lock);
	return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
	ssize_t retval = count, i = 0;
	char* lBuffptr = NULL;
	// remove this
	struct aesd_dev* aDev = (struct aesd_dev*)filp->private_data;
	struct aesd_buffer_entry ret = 
	{
		.buffptr = NULL,
		.size = 0
	};
	//PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
	/**
	 * TODO: handle write
	 */
	
	//printk(KERN_INFO "Mallocing %ld bytes.\n", count);
	*f_pos = 0;	
	if(aDev->isComplete)
	{
		aDev->element->buffptr = kmalloc(count*sizeof(uint8_t), GFP_KERNEL);
		if(aDev->element->buffptr == NULL)
		{
			//printk(KERN_ERR "Mallocing failed %d.\n", __LINE__);
			return -EFAULT;
		}
		aDev->element->size = 0;
		printk(KERN_INFO "Malloc %p\n", aDev->element->buffptr);
		lBuffptr = aDev->element->buffptr;
	}
	else if(!aDev->isComplete)
	{
		aDev->element->buffptr = krealloc(aDev->element->buffptr, (aDev->element->size + count), GFP_KERNEL);	

		if(aDev->element->buffptr == NULL)
		{
			//printk(KERN_ERR "reallocing failed %d.\n", __LINE__);
			return -EFAULT;
		}
		else
		{
			printk(KERN_INFO "Passed realloc %ld, %ld\n", aDev->element->size, count);
			lBuffptr = aDev->element->buffptr + aDev->element->size;
		}
	}
	if(!copy_from_user(lBuffptr, buf, count))
	{
		//printk(KERN_INFO "Successful in copying %ld bytes. %s %s\n", count, lBuffptr, aDev->element->buffptr);

		aDev->element->size += count;
		retval = count;
	}
	else
	{
		//printk(KERN_ERR "Unuccessful in copying %ld bytes.\n", count);
		return -EFAULT;
	}

	for (i = 0; i < aDev->element->size; i++)
	{
		if (lBuffptr[i] == '\n')
		{
			printk(KERN_INFO "New line found.\n");
			// reset the flag
			aDev->isComplete = 1;	

			if (mutex_lock_interruptible(&aDev->lock) != 0)
			{
				printk(KERN_INFO "Mutex failed to aquire.\n");
				return -EFAULT;
			}
			
			// add the entry to the circular buffer
			ret = aesd_circular_buffer_add_entry(&aDev->circularBuffer, aDev->element);
			mutex_unlock(&aDev->lock);
			
			aDev->element->size = 0;
			if(ret.buffptr != NULL)
			{	
				printk(KERN_INFO "Freeing memory. %p\n", ret.buffptr);
				kfree(ret.buffptr);
				ret.buffptr = NULL;
			}
			
		}
		else 
		{
			aDev->isComplete = 0;
		}
		
	}

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


	aesd_device.isComplete = 1;
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
	int cntr = 0;
	struct aesd_buffer_entry *element;
	dev_t devno = MKDEV(aesd_major, aesd_minor);

	cdev_del(&aesd_device.cdev);

	/**
	 * TODO: cleanup AESD specific poritions here as necessary
	 */
	AESD_CIRCULAR_BUFFER_FOREACH(element, &aesd_device.circularBuffer, cntr) 
	{
		if(element->buffptr != NULL)
		{
			kfree(element->buffptr);
			element->size = 0;
		}
	}
	
	if(aesd_device.element != NULL)
	{
		kfree(aesd_device.element);
	}

	mutex_destroy(&aesd_device.lock);
	unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
