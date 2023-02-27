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

#define BUFFER_SIZE 		  100
#define PORT_NUMBER 		"9000"
#define PATH_TO_FILE 		"/var/tmp/aesdsocketdata.txt"
#define MAX_PENDING_CONNECTIONS  10

int sock_fd,conn_fd; 

struct addrinfo hints;
struct addrinfo *servinfo;
struct sockaddr_in clt_addr; 

char *h_dynamic_buff = NULL;

void signal_handler(int signal_t)
{
	if(signal_t==SIGINT){
		syslog(LOG_INFO,"Ctrl+C Signal. Terminating\n");
	}
	else if(signal_t==SIGTERM){
		syslog(LOG_INFO,"SIGTERM received. Gracefully terminating\n");
	}
	else{
		syslog(LOG_INFO,"Received Unanticipated signal %d\n", signal_t);
		exit(EXIT_FAILURE);
	}
	unlink(PATH_TO_FILE);
	//Close socket and client connection
	close(sock_fd);
	close(conn_fd);
	
	exit(0); //Exit success 
}


int main(int argc, char *argv[])
{ 
	char input_buffer[BUFFER_SIZE]; 		//buffer to store the packets byte
	bool packet_received=false;
	int file_fd =0; 
	int packet_bytes =0;
	int total_packets =0; 
	int rec_status =0, i =0;
	socklen_t address_len=sizeof(struct sockaddr); 
	
	openlog(NULL,0, LOG_USER); 			//To setup logging with LOG_USER
	
	//To start a daemon process
	if((argc>1) && strcmp(argv[1],"-d")==0)
	{
		if(daemon(0,0)==-1) {
			syslog(LOG_ERR, "Unable to Enter Daemon Mode\n");
			exit(1);
		}
	}
	if(signal(SIGINT,signal_handler)==SIG_ERR)
	{
		syslog(LOG_ERR,"SIGINT failed");
		exit(EXIT_FAILURE);
	}
	if(signal(SIGTERM,signal_handler)==SIG_ERR)
	{
		syslog(LOG_ERR,"SIGTERM failed");
		exit(EXIT_FAILURE);
	}
	
	//create socket for IPC
	sock_fd=socket(PF_INET, SOCK_STREAM, 0);
	if(sock_fd==-1) {
		syslog(LOG_ERR, "Unable to create asocket\n");
		exit(EXIT_FAILURE);
	}
	//Get server address
	hints.ai_flags=AI_PASSIVE; 
	if(getaddrinfo(NULL,PORT_NUMBER,&hints,&servinfo) !=0) {
		syslog(LOG_ERR, "Unable to get the server's address\n");
		exit(EXIT_FAILURE);
	}
	
	//Bind the socket 
	if(bind(sock_fd,servinfo->ai_addr,sizeof(struct sockaddr)) == -1) {
		syslog(LOG_ERR, "Unable to Bind\n");
		freeaddrinfo(servinfo); 			//Freeing the memory created by socket address before exiting 
		exit(EXIT_FAILURE);
	}
	freeaddrinfo(servinfo); 				//Freeing the memory created by socket address
	
	file_fd=open(PATH_TO_FILE, O_WRONLY|O_CREAT|O_TRUNC, S_IRWXU|S_IRGRP|S_IROTH); 	//Creating a new file with 744 octal value
	if (file_fd==-1) {
		syslog(LOG_ERR, "Unable to create the file\n");
		exit(EXIT_FAILURE);
	}
	close(file_fd);

	//Looping for all the connections from Client
	while(1)
	{
		if(listen(sock_fd,MAX_PENDING_CONNECTIONS) == -1) {		//Will start rejecting after 32 pending connections 
			syslog(LOG_ERR, "Unable to Listen to the Clients\n");
			exit(EXIT_FAILURE);
		}
		conn_fd = accept(sock_fd,(struct sockaddr *)&clt_addr,&address_len);
		if(conn_fd==-1) {
			syslog(LOG_ERR, "Unable to Accept the Connection\n");
			exit(EXIT_FAILURE);
		}
		syslog(LOG_INFO,"Accepts connection from %s",inet_ntoa(clt_addr.sin_addr));
		printf("Accepts connection from %s\n",inet_ntoa(clt_addr.sin_addr));
		h_dynamic_buff = (char*)malloc(sizeof(char) * BUFFER_SIZE); //Allocate size equal to buffer size
		if(h_dynamic_buff==NULL) {
			syslog(LOG_ERR, "Malloc Failure.Unable to Allocate Memory\n");
			exit(EXIT_FAILURE);
		}
		memset(h_dynamic_buff,0,BUFFER_SIZE); //Reset the temporary buffer
		packet_received=false;
		while(!packet_received)
		{
		rec_status=recv(conn_fd,input_buffer,100,0); //Receive data packets from client
		if(rec_status==-1)
		{
			syslog(LOG_ERR, "Error in reception of data packets from client");
			exit(EXIT_FAILURE);
		}
		for(i=0;i<BUFFER_SIZE;i++)
		{
			if(input_buffer[i]=='\n')
			{
				i++;
				packet_received=true;
				break;
			}	
			
		}
		packet_bytes+=i;
		h_dynamic_buff=(char *)realloc(h_dynamic_buff,packet_bytes);
		if(h_dynamic_buff==NULL)
		{
			syslog(LOG_ERR, "Reallocation of memory failed");
			exit(EXIT_FAILURE);
		}
		memcpy(h_dynamic_buff+packet_bytes-i,input_buffer,i); 
		memset(input_buffer,0,BUFFER_SIZE); 
		}

		file_fd = open(PATH_TO_FILE,O_APPEND | O_WRONLY); 		//Open the file to write from current position
		if(file_fd==-1) {
			printf("Unable to open in write mode\n");
			syslog(LOG_ERR, "Unable to open the File\n");
			exit(EXIT_FAILURE);
		}
		if(write(file_fd,h_dynamic_buff,packet_bytes) !=packet_bytes) {
			printf("Unable to write\n");
			syslog(LOG_ERR, "All Bytes not written to the file\n");
			exit(EXIT_FAILURE);
		}
		close(file_fd);

		total_packets += packet_bytes; 			
		char send_buffer[total_packets]; 			        //Storing contents to send
		file_fd=open(PATH_TO_FILE,O_RDONLY); 				//Opening file to Read 
		if(file_fd==-1) {
			//printf("Unable to open in read mode\n");
			syslog(LOG_ERR, "Unable to open the File\n");
			exit(EXIT_FAILURE);
		}

		if(read(file_fd,&send_buffer,total_packets)==-1) {  	//Read the file and storing contents in a buffer
			//printf("Unable to read the file\n");
			syslog(LOG_ERR, "Unable to Read from the file. Check Permissions\n");
			exit(EXIT_FAILURE);
		}	
		
		//Send data packet to the client 
		if(send(conn_fd,&send_buffer,total_packets,0)==-1) {
			//printf("Unable to send the contents\n");
			syslog(LOG_ERR, "Unable to send the buffer Contents to the client\n");
			exit(EXIT_FAILURE);
		}
		packet_bytes =0; //Reset total bytes before sending new packet
		close(file_fd);
		free(h_dynamic_buff);
		syslog(LOG_ERR,"Closed connection with %s\n",inet_ntoa(clt_addr.sin_addr));
		printf("Closed connection with %s\n",inet_ntoa(clt_addr.sin_addr));
	}
	closelog(); //Close syslog
	return 0;
}
