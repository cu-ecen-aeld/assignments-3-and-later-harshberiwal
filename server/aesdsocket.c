#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#define BUFFER_SIZE 		  100
#define PORT_NUMBER 		"9000"
#define PATH_TO_FILE 		"/var/tmp/aesdsocketdata.txt"
#define MAX_PENDING_CONNECTIONS  10

int sock_fd;
bool signal_interrupted = false;

void signal_handler(int signal_t)
{
	if(signal_t==SIGINT){
		syslog(LOG_INFO,"Ctrl+C Signal. Terminating\n");
	}
	else if(signal_t==SIGTERM){
		syslog(LOG_INFO,"SIGTERM received. Gracefully terminating\n");
	}
	//Close socket and client connection
	signal_interrupted = true; 
	close(sock_fd);
}

int main(int argc, char *argv[])
{ 
	int file_fd =0, total_packets =0,packet_bytes =1,recv_status =0,nl_char_received =0,all_received =0, conn_fd=0; 
	char *h_dynamic_buff = NULL;
	socklen_t address_len=sizeof(struct sockaddr); 
	struct addrinfo hints, *servinfo;
	struct sockaddr_in clt_addr; 
	
	openlog(NULL,0, LOG_USER); 			//To setup logging with LOG_USER
	
	if(signal(SIGINT,signal_handler)==SIG_ERR)
	{
		syslog(LOG_ERR,"SIGINT failed");
		return -1; 
	}

	if(signal(SIGTERM,signal_handler)==SIG_ERR)
	{
		syslog(LOG_ERR,"SIGTERM failed");
		return -1; 
	}

	//Get server address
	memset(&hints,0,sizeof(hints));
	hints.ai_flags=AI_PASSIVE; //Set this flag before passing to function
	hints.ai_family=AF_INET;
	hints.ai_socktype=SOCK_STREAM;
	if(getaddrinfo(NULL,PORT_NUMBER,&hints,&servinfo) !=0) {
		syslog(LOG_ERR, "Unable to get the server's address: %s \n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	
	//create socket for IPC
	sock_fd=socket(PF_INET, SOCK_STREAM, 0);
	if(sock_fd==-1) {
		syslog(LOG_ERR, "Unable to create asocket\n");
		exit(EXIT_FAILURE);
	}
	//Bind the socket 
	if(bind(sock_fd,servinfo->ai_addr,sizeof(struct sockaddr)) == -1) {
		printf("Unable to Bind\n");
		syslog(LOG_ERR, "Unable to Bind%s \n", strerror(errno));
		freeaddrinfo(servinfo); 			//Freeing the memory created by socket address before exiting 
		exit(EXIT_FAILURE);
	}
	freeaddrinfo(servinfo); 				//Freeing the memory created by socket address
	
	if(listen(sock_fd,MAX_PENDING_CONNECTIONS) == -1) {		//Will start rejecting after 32 pending connections 
		syslog(LOG_ERR, "Unable to Listen to the Clients%s \n", strerror(errno));
		exit(EXIT_FAILURE);
	}	

	//To start a daemon process
	if((argc>1) && strcmp(argv[1],"-d")==0)
	{
		if(daemon(0,0)==-1) {
			syslog(LOG_ERR, "Unable to Enter Daemon Mode\n");
			exit(1);
		}
	}

	file_fd=open(PATH_TO_FILE, O_WRONLY|O_CREAT|O_TRUNC, S_IRWXU|S_IRGRP|S_IROTH); 	//Creating a new file with 744 octal value
	if (file_fd==-1) {
		syslog(LOG_ERR, "Unable to create the file%s \n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	close(file_fd);

	//Looping for all the connections from Client
	while(!signal_interrupted)
	{
		conn_fd = accept(sock_fd,(struct sockaddr *)&clt_addr,&address_len);
		if(conn_fd==-1) {
			syslog(LOG_ERR, "Unable to Accept the Connection: %s \n", strerror(errno));
			break;
		}
		else {
			syslog(LOG_INFO,"Accepts connection from %s",inet_ntoa(clt_addr.sin_addr));
			printf("Accepts connection from %s\n",inet_ntoa(clt_addr.sin_addr));
		}
		
		h_dynamic_buff = (char*)malloc(sizeof(char));
     	if (h_dynamic_buff == NULL){
         	syslog(LOG_ERR,"Malloc Failure. Couldn't allocate Initial Memory\n");
         	return -1;
     	}
		
     	all_received =0;
		packet_bytes =1;

     	while (!all_received && !signal_interrupted){
			nl_char_received = 0;
			while((!nl_char_received) && (!all_received) && (!signal_interrupted)){
				recv_status = recv(conn_fd,h_dynamic_buff+packet_bytes-1,1,0);
				if (recv_status == -1){
					syslog(LOG_ERR,"Unable to Recv Correctly\n");
					return -1; 
				}
				else if (recv_status == 0){	    
					all_received = 1;   
					packet_bytes--;     
					syslog(LOG_INFO,"Closing Connection. All Bytes Received");     
				}
				else{
					if (h_dynamic_buff[packet_bytes-1] == '\n'){
						nl_char_received = 1;
					}
					else{
						packet_bytes ++;
						h_dynamic_buff = realloc(h_dynamic_buff, (packet_bytes)*sizeof(char)); //allocate
						if (h_dynamic_buff == NULL){
							syslog(LOG_ERR,"Realloc Failure. Couldn't allocate Additional Memory\r\n");
							return -1;
						}
					}
				}
			}
			if (nl_char_received) {   
				file_fd = open(PATH_TO_FILE, O_APPEND | O_WRONLY); //Open the file in write only
				if(file_fd==-1) {
					syslog(LOG_ERR, "Could not open the file");
					return -1; 
				}
				if(write(file_fd, h_dynamic_buff,packet_bytes) < packet_bytes) {
					syslog(LOG_ERR,"Unable to Write all the bytes\n");
					return -1; 
				}
				total_packets+=packet_bytes;
				packet_bytes = 1; 	   				
				h_dynamic_buff = realloc(h_dynamic_buff, (packet_bytes)*sizeof(char)); 
				if (h_dynamic_buff == NULL){
					syslog(LOG_ERR,"Realloc Failure. Can't Resize");
					return -1; 
				}
				close(file_fd); 

				file_fd=open(PATH_TO_FILE,O_RDONLY); //Open file to read only
				if(file_fd==-1)
				{
					syslog(LOG_ERR, "Unable to open the file in Read Mode\n");
					return -1;
				}		
				char send_buffer[total_packets]; 			        //Storing contents to send
				file_fd=open(PATH_TO_FILE,O_RDONLY); 				//Opening file to Read 
				if(file_fd==-1) {
					printf("Unable to open in read mode\n");
					syslog(LOG_ERR, "Unable to open the File: %s \n", strerror(errno));
					return -1; 
				}

				if(read(file_fd,&send_buffer,total_packets)==-1) {  	//Read the file and storing contents in a buffer
					printf("Unable to read the file\n");
					syslog(LOG_ERR, "Unable to Read from the file. Check Permissions: %s \n", strerror(errno));
					return -1; 
				}	
				
				//Send data packet to the client 
				if(send(conn_fd,&send_buffer,total_packets,0)==-1) {
					printf("Unable to send the contents\n");
					syslog(LOG_ERR, "Unable to send the buffer Contents to the client:%s \n", strerror(errno));
					return -1;
				}
				close(file_fd);
			}
		}
		free(h_dynamic_buff);
		syslog(LOG_ERR,"Closed connection with %s\n",inet_ntoa(clt_addr.sin_addr));
		printf("Closed connection with %s\n",inet_ntoa(clt_addr.sin_addr));
	}
	close(conn_fd);
	unlink(PATH_TO_FILE);
	closelog(); //Close syslog
	return 0;
}