#!/bin/bash
filesdir=$1
searchstr=$2

#Checking for Valid Number of Arguments
if [ $# -eq 2 ]
then 
	: 
else
	echo "Invalid Number of Arguments." 
	echo "Number of Valid arguments is 2" 
	echo "Argument 1: File Path Directory"
	echo "Argument 2: String to be searched in the specified directory Path" 
	exit '1'
fi 

#Checking for Valid Directory
if [ -d ${filesdir} ]
then 
	:
else 	
	echo "Invalid Directory" 
	exit '2'
fi

#Moving to Path Directory
cd ${filesdir}

#Calculating Number of matching Files 
X=$(grep -lr ${searchstr} * | wc -l)

#Calculating Number of matching lines
Y=$(grep -r ${searchstr} * | wc -l)
echo "The number of files are ${X} and the number of matching lines are ${Y}"


