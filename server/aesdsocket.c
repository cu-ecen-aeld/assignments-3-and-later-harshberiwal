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
#include "queue.h"
#include "pthread.h"
#include "sys/time.h" 

#define BUFFER_SIZE 		 100
#define PORT_NUMBER 		"9000"
#define PATH_TO_FILE 		"/var/tmp/aesdsocketdata.txt"
#define MAX_PENDING_CONNECTIONS  10

int sock_fd;
bool signal_interrupted = false;
pthread_mutex_t mutex; 
int total_packets =0; 
int g_datafd= 0; 

typedef struct thread_nodes{
	pthread_t thread; 
	int confd; 
	bool complete_success_flag; 
	SLIST_ENTRY(thread_nodes) entries; 
}thread_nodes_t; 

void sig_alarm_handler(int signo){
    time_t time_now;
    time_t ret = time(&time_now);
    if(ret == -1){
        syslog(LOG_ERR,"Unable to get the Time\r\n");
        return;
    }
    struct tm tm_now;
    localtime_r(&time_now,&tm_now);
    char time_buff[BUFFER_SIZE];
    size_t time_str_size = strftime(time_buff,BUFFER_SIZE,"timestamp:%a, %d %b %Y %T %z\n",&tm_now);
    if (!time_str_size){
        syslog(LOG_ERR,"Unable to get the Timestamp\n");
        return;
    }
	pthread_mutex_lock(&mutex);
	g_datafd = open(PATH_TO_FILE, O_WRONLY | O_APPEND); 
	if(g_datafd == -1){
		syslog(LOG_ERR,"Couldn't open the file\n");
		return;
	}
	total_packets +=time_str_size; 
	if((write(g_datafd, time_buff,time_str_size)) < time_str_size) {
		 syslog(LOG_ERR,"Unable to write the Timestamp\n");
		return;
	}
	close(g_datafd);
	pthread_mutex_unlock(&mutex);
    return;
}

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

void timer_init() {
	struct itimerval ts_delay;
	ts_delay.it_value.tv_sec = 10;	  // Inital delay
	ts_delay.it_value.tv_usec = 0;	  
	ts_delay.it_interval.tv_sec = 10; // repeated interval
	ts_delay.it_interval.tv_usec = 0; 

	tzset();

	if(setitimer(ITIMER_REAL, &ts_delay, NULL)) {
		perror("settimer failure");
		return;
	}
}

void* thread_connection_func(void* thread_node_params) {
	char *h_dynamic_buff = NULL; 
	int file_fd =0, packet_bytes =1,recv_status =0,nl_char_received =0,all_received =0;
	if(thread_node_params == NULL){
  		return NULL;
	}
	thread_nodes_t *t_node_params= (thread_nodes_t *)thread_node_params;
	h_dynamic_buff = (char*)malloc(sizeof(char));
     	if (h_dynamic_buff == NULL) {
         	syslog(LOG_ERR,"Malloc Failure. Couldn't allocate Initial Memory\n");
         	t_node_params->complete_success_flag = true;
			close(t_node_params->confd); 
			return NULL;
     	}	
     	while (!all_received && !signal_interrupted){
			nl_char_received = 0;
			while((!nl_char_received) && (!all_received) && (!signal_interrupted)){
				recv_status = recv(t_node_params -> confd,h_dynamic_buff+packet_bytes-1,1,0);
				if (recv_status == -1){
					syslog(LOG_ERR,"Unable to Recv Correctly\n");
					t_node_params->complete_success_flag= true;
					close(t_node_params->confd); 
					pthread_exit(NULL);
					return NULL;
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
							t_node_params->complete_success_flag= true;
							close(t_node_params->confd); 
							pthread_exit(NULL);
							return NULL;
						}
					}
				}
			}
		
			if (nl_char_received) {
				pthread_mutex_lock(&mutex); 
				file_fd = open(PATH_TO_FILE, O_APPEND | O_WRONLY); //Open the file in write only
				if(file_fd==-1) {
					syslog(LOG_ERR, "Could not open the file");
					t_node_params->complete_success_flag= true;
					close(t_node_params->confd); 
					return NULL;
				} 
				if(write(file_fd, h_dynamic_buff,packet_bytes) < packet_bytes) {  //Writing to the File 
					syslog(LOG_ERR,"Unable to Write all the bytes\n");
					t_node_params->complete_success_flag= true;
					close(t_node_params->confd); 
					return NULL;
				}
				close(file_fd);
				total_packets+=packet_bytes;
				pthread_mutex_unlock(&mutex); 
				packet_bytes = 1; 	   				
				h_dynamic_buff = realloc(h_dynamic_buff, (packet_bytes)*sizeof(char)); 
				if (h_dynamic_buff == NULL){
					syslog(LOG_ERR,"Realloc Failure. Can't Resize");
					t_node_params->complete_success_flag= true;
					close(t_node_params->confd); 
					return NULL;
				}
				pthread_mutex_lock(&mutex);
				file_fd=open(PATH_TO_FILE,O_RDONLY); 					//Opening file to Read 
				if(file_fd==-1) {
					printf("Unable to open in read mode\n");
					syslog(LOG_ERR, "Unable to open the File: %s \n", strerror(errno));
					t_node_params->complete_success_flag= true;
					close(t_node_params->confd); 
					return NULL;
				}
				char send_buffer[total_packets]; 			        	//Storing contents to send
				if(read(file_fd,&send_buffer,total_packets)==-1) {  	//Read the file and storing contents in a buffer
					printf("Unable to read the file\n");
					syslog(LOG_ERR, "Unable to Read from the file. Check Permissions: %s \n", strerror(errno));
					t_node_params->complete_success_flag= true;
					close(t_node_params->confd); 
					return NULL;
				}	
				close(file_fd);
				pthread_mutex_unlock(&mutex); 
				
				if(send(t_node_params ->confd,&send_buffer,total_packets,0)==-1) { 	//Send data packet to the client 
					printf("Unable to send the contents\n");
					syslog(LOG_ERR, "Unable to send the buffer Contents to the client:%s \n", strerror(errno));
					t_node_params->complete_success_flag= true;
					close(t_node_params->confd); 
					return NULL;
				} 
			}
		}
		close(t_node_params->confd); 
		syslog(LOG_INFO,"Closed connection"); 
		free(h_dynamic_buff);
		t_node_params->complete_success_flag = true;     
		pthread_exit(NULL);
}


int main(int argc, char *argv[])
{ 
	int conn_fd=0;
	socklen_t address_len=sizeof(struct sockaddr); 
	struct addrinfo hints, *servinfo;
	struct sockaddr_in clt_addr; 
	thread_nodes_t *t_node; 
	int total_conn =0 ; 
	int file_fd; 
	thread_nodes_t *node = NULL;
	thread_nodes_t *ptr = NULL;

	openlog(NULL,0, LOG_USER); 			//To setup logging with LOG_USER
	printf("pid is %d\n", getpid());

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

	SLIST_HEAD(slisthead,thread_nodes) head = SLIST_HEAD_INITIALIZER(head);
    SLIST_INIT(&head);

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
	sock_fd=socket(AF_INET, SOCK_STREAM, 0);
	if(sock_fd==-1) {
		syslog(LOG_ERR, "Unable to create asocket\n");
		exit(EXIT_FAILURE);
	}

	//Bind the socket 
	if(bind(sock_fd,servinfo->ai_addr,sizeof(struct sockaddr)) == -1) {
		printf("Unable to Bind\n");
		syslog(LOG_ERR, "Unable to Bind%s \n", strerror(errno));
		freeaddrinfo(servinfo); 							//Freeing the memory created by socket address before exiting 
		close(sock_fd);
		exit(EXIT_FAILURE);
	}
	freeaddrinfo(servinfo); 								//Freeing the memory created by socket address
	
	if(listen(sock_fd,MAX_PENDING_CONNECTIONS) == -1) {		//Will start rejecting after 32 pending connections 
		syslog(LOG_ERR, "Unable to Listen to the Clients%s \n", strerror(errno));
		close(sock_fd);
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

	file_fd = open(PATH_TO_FILE,(O_RDWR|O_CREAT|O_TRUNC), S_IRWXU|S_IRGRP|S_IROTH); 	//Creating a new file with 744 octal value
 	if (file_fd==-1) {
		syslog(LOG_ERR, "Unable to create the file%s \n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	close(file_fd); 
	
	// Initialize mutex for packet data file
	pthread_mutex_init(&mutex, NULL); 

	signal(SIGALRM, sig_alarm_handler);

	timer_init(); 											//Initializing timer 

	while (!signal_interrupted)
	{
		conn_fd = accept(sock_fd,(struct sockaddr *)&clt_addr,&address_len);
		if(conn_fd==-1) {
			syslog(LOG_ERR, "Unable to Accept the Connection: %s \n", strerror(errno));
			break;
		}
		else {
			t_node = (struct thread_nodes *)malloc(sizeof(struct thread_nodes));  
			t_node-> complete_success_flag = false;									
			t_node-> confd = conn_fd;
			syslog(LOG_INFO,"Accepts connection from %s",inet_ntoa(clt_addr.sin_addr));
			printf("Accepts connection from %s\n",inet_ntoa(clt_addr.sin_addr));
			if(pthread_create(&t_node -> thread, NULL, thread_connection_func, t_node) != 0){
				 syslog(LOG_ERR, "Couldn't create a thread: %s", strerror(errno));
				 goto thread_kill;
			} 
			if(total_conn == 0){
				SLIST_INIT(&head);
				SLIST_INSERT_HEAD(&head, t_node, entries); 
				total_conn++;
			}
			else{
				SLIST_INSERT_HEAD(&head, t_node, entries); 
				total_conn++;
			}
			
			SLIST_FOREACH_SAFE(node, &head, entries, ptr){
				if(node -> complete_success_flag){
					 pthread_join(node->thread,NULL); 
                     SLIST_REMOVE(&head, node, thread_nodes, entries);
                     free(node);
                     syslog(LOG_INFO,"Closing Thread Connection %d\n",--total_conn);
				}
			}  
		}	
	}

thread_kill:
	syslog(LOG_INFO,"Checking if all threads are Killed");
  	SLIST_FOREACH_SAFE(node, &head, entries, ptr){
         pthread_kill(node->thread,SIGINT);
         pthread_join(node->thread,NULL); 
         SLIST_REMOVE(&head, node, thread_nodes, entries);
         free(node);
         syslog(LOG_INFO,"Killing all threads: %d\n",--total_conn);
    }
	
	close(file_fd);
	close(conn_fd);
	unlink(PATH_TO_FILE);
	closelog(); //Close syslog
	return 0;
}