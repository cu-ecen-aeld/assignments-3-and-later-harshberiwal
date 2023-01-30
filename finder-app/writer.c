/****************************************************************************************
@Author 	Harsh Beriwal (harsh.beriwal@colorado.edu)

@course 	Advanced Embedded Software Development
@instructor	Daniel Walkes 
****************************************************************************************/

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h> 
#include <stdlib.h>
#include <string.h> 

int main (int argc, char *argv[])
{
	int fd; 
	ssize_t wr_fl; 
	openlog(NULL, 0 , LOG_USER);     
	char *writefile = argv[1];					 //Storing Arguments in the Writefile and WriteStr
	char *writestr = argv[2];
	if(argc !=3){
		syslog(LOG_ERR, "Invalid Number of Arguments: %d", (argc -1)); 
		printf("Incorrect Number of Arguments\n");
		printf("Number of Valid arguments is 2\n");
		printf("Argument 1: Path to a File\n");
		printf("Argument 2: String to be written within the specified file\n");
		exit(1);    				
	}
	else {
		fd = open (writefile, O_CREAT | O_WRONLY | O_TRUNC , 777); 
		if(fd == -1) {
			syslog(LOG_ERR, "Unable to Open the File\n");	 //No File Descriptor Returned 
		}
		else { 
			syslog(LOG_DEBUG, "Writing %s to %s", writestr, writefile); 
			wr_fl = write(fd, writestr, strlen(writestr)); 	
			if(wr_fl != strlen(writestr)){		 //If number of bytes returned is correct
				syslog(LOG_ERR, "Unable to write the string %s", writestr); 
			}
			close(fd);  					 //Closing the Opened file 
		}
	}
	return 0; 
}
