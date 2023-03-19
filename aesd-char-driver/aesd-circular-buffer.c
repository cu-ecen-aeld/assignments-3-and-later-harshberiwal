/**
 * @file aesd-circular-buffer.c
 * @brief Functions and data related to a circular buffer imlementation
 *
 * @author Dan Walkes
 * @date 2020-03-01
 * @copyright Copyright (c) 2020
 *
 */

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

#include "aesd-circular-buffer.h"

/**
 * @param buffer the buffer to search for corresponding offset.  Any necessary locking must be performed by caller.
 * @param char_offset the position to search for in the buffer list, describing the zero referenced
 *      character index if all buffer strings were concatenated end to end
 * @param entry_offset_byte_rtn is a pointer specifying a location to store the byte of the returned aesd_buffer_entry
 *      buffptr member corresponding to char_offset.  This value is only set when a matching char_offset is found
 *      in aesd_buffer.
 * @return the struct aesd_buffer_entry structure representing the position described by char_offset, or
 * NULL if this position is not available in the buffer (not enough data is written).
 */
struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos(struct aesd_circular_buffer *buffer,
            size_t char_offset, size_t *entry_offset_byte_rtn )
{
    /**
    * TODO: implement per description
    */

   size_t upd_offset=char_offset+1;
   int buff_length=AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
   uint8_t temp_store=buffer->out_offs;


   while (buff_length!=0) //Check the entire buffer
   {
        if(buffer->entry[temp_store].size<upd_offset) //If the entry size is less than offset
        {
            upd_offset=upd_offset-buffer->entry[temp_store].size; //Update the offset 
            if(temp_store==AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED-1) //Cycle back to start entry
                temp_store=0;
            else
                temp_store++;
        }
        else
        {
            *entry_offset_byte_rtn = upd_offset-1; //return the offset in the entry
            return &buffer->entry[temp_store]; //Return the entry
        }
        buff_length--;
   }
   return NULL;
}

/**
* Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
* If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
* new start location.
* Any necessary locking must be handled by the caller
* Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
*/
const char *aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    /**
    * TODO: implement per description
    */

    const char *freebuffer=NULL; //Pointer to return the replaced buffer entry to be freed by kernel driver

   //Condition to check if the buffer is full
   if((buffer->in_offs==buffer->out_offs)&&buffer->full)
   {
        if(buffer->out_offs==(AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED-1)) //If the enqueue is done on last element
            buffer->out_offs=0; //Cycle back the read variable to zero
        else
            buffer->out_offs++; 

        freebuffer = buffer->entry[buffer->in_offs].buffptr; //Store the address of the entry being replaced with a new entry

        buffer->entry[buffer->in_offs]=*add_entry; //replace existing data
        buffer->in_offs=buffer->out_offs; //Update write variable
   }
   else //Operations when buffer isn't full
   {
        if (buffer->in_offs==(AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED-1)) //Cycling back
        {
             buffer->entry[buffer->in_offs]=*add_entry;
             buffer->in_offs=0;
        }
        else 
        {
            buffer->entry[buffer->in_offs]=*add_entry;
            buffer->in_offs++;
        }

        if(buffer->in_offs == buffer->out_offs) //Turn flag true if read and write point to same entry 
            buffer->full=true;
   }
   return freebuffer; //Return the pointer to the replaced entry
   
}

/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer,0,sizeof(struct aesd_circular_buffer));
}
