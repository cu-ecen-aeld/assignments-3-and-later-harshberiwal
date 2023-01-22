#!/bin/bash 

writefile=$1
writestr=$2

#Checking for Valid Number of Arguments 
if [ $# -eq 2 ]
then 
	:	 
else
	echo "Invalid Number of Arguments." 
	echo "Number of Valid arguments is 2" 
	echo "Argument 1: Path to a File"
	echo "Argument 2: String to be written within the specified file" 
	exit '1'
fi 

#Creating Directory if not present
mkdir -p $(dirname ${writefile})

#Printing String on the File. 
echo ${writestr} > ${writefile}
