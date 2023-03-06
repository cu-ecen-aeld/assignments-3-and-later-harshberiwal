#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <linux/fs.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>

// Macros for socket communication
#define BACKLOG   (20u)
#define BUFFER_SIZE  (512u)
#define PORT_NUMBER ("9000")

// Macro for error and success
#define SUCCESS (0u)
#define ERROR  (-1)

// Global - File path
const char* file_path = "/var/tmp/aesdsocketdata";


// Global - The file and socket descriptors are global for being to able take action in the signal handler
int sd = 0;
int fd = 0;

// Global - Flag to track if the execution was complete
int is_exec_complete = 0;

// Global - Flag to track if SIGALARM was triggered
int is_alarm = 0;

// Global - Mutex lock for thread synchronization
pthread_mutex_t mutex;


/*************************LINKED LIST********************************/
// Linked list structures definition
// Linked list data structure - Holds thread attributes
typedef struct{
    pthread_t tid;  // Thread ID
    bool is_complete;  // To track if thread is completed
    int conn_fd;  // Connection file descriptor
    struct sockaddr_in *client_addr; // Client Address
}thread_data_t;

typedef struct ll_node{
    thread_data_t thread_data; // Data field for linked list
    struct ll_node *next;   // Holds the next pointer
} node_t;

// Linked list - Add node to the head
void addFirst(node_t **head_ref , node_t *new_node)
{
    new_node->next = (*head_ref);
    (*head_ref) = new_node;
}
/********************************************************************/

/***************************TIMER***********************************/
// Global - Timer variables
timer_t timer;

// Timer functions

// Function to create a timer
static int createTimer()
{
    int ret_status = 0;

    // Create a timer
    ret_status = timer_create(CLOCK_REALTIME, NULL, &timer);
    if(ERROR == ret_status)
    {
        syslog(LOG_ERR , "timer create\n");
        // printf("Creating time error: %d\n", errno);
        return ERROR;
    }

    // struct itimerval delay;
    struct itimerspec delay;

    // One time 
    delay.it_value.tv_sec = 10;
    delay.it_value.tv_nsec = 0;
    // Set 10 sec interval timer
    delay.it_interval.tv_sec = 10;
    delay.it_interval.tv_nsec = 0;

    // Set the timer
    ret_status = timer_settime(timer, 0, &delay, NULL);
    // Error check
    if (ret_status != SUCCESS) {
        // printf("Setting time error: %d\n", errno);
        syslog(LOG_ERR , "timer settime\n");
        return ERROR;
    }

    return SUCCESS;
}

// Function to write timestamp value to file
static int logTimestamp()
{
    time_t timestamp;
    char time_buffer[40];
    char buffer[100];
    int ret_status = 0;

    struct tm* time_stamp;


    time(&timestamp);
    time_stamp = localtime(&timestamp);

    // Reference : https://man7.org/linux/man-pages/man3/strftime.3.html
    strftime(time_buffer, 40, "%a, %d %b %Y %T %z", time_stamp);
    sprintf(buffer, "timestamp:%s\n", time_buffer);

    syslog(LOG_DEBUG , "Time: %s\n", buffer);

    lseek(fd, 0, SEEK_END);

    // Acquire lock before writing to the file
    ret_status = pthread_mutex_lock(&mutex);
    // Error check
    if (ret_status != SUCCESS){
        printf("Mutex lock %d\n", errno);
        syslog(LOG_ERR , "lock\n");
    }


    // Write timestamp to the file
    ret_status = write(fd, buffer, strlen(buffer));
    // Error check
    if (ERROR == ret_status) {
        // printf("Write: %d\n", errno);
        syslog(LOG_ERR , "write\n");
    }

    // Release the lock
    ret_status = pthread_mutex_unlock(&mutex);
    // Error check
    if (ret_status != SUCCESS){
        // printf("Mutex unlock: %d\n", errno);
        syslog(LOG_ERR , "lock\n");
    }

    return SUCCESS;
}
/********************************************************************/


/***************************DAEMON***********************************/
// Daemon function
int createDaemon()
{
    int ret_status = 0;

    pid_t pid;

    // Fork a new child process
    pid = fork ();
    // Error check
    if (pid == -1){
        syslog(LOG_ERR , "fork\n");
        return -1;
    }
    else if (pid != 0){
        exit (EXIT_SUCCESS);
    }
        
    // Next step of creating a daemon is to begin a session 
    ret_status = setsid();   
    if (ret_status == -1){
        syslog(LOG_ERR , "setsid\n");
        return -1;
    }
        
    // Switch to the root directory
    ret_status = chdir("/");
    if (ret_status == -1){
        syslog(LOG_ERR , "chdir\n");
        return -1;
    }
        
    // Redirect the stdin , stdout and stderror to /dev/null
    open ("/dev/null", O_RDWR);
    ret_status = dup (0); 
    if (ret_status == -1){
        syslog(LOG_ERR , "dup\n");
        return -1;
    }
    ret_status = dup (0); 
    if (ret_status == -1){
        syslog(LOG_ERR , "dup\n");
        return -1;
    }
    return 0;
}
/********************************************************************/

// Signal handler for SIGINT, SIGTERM and SIGALRM signals
void signalHandler(int signal)
{
    switch(signal){
        case SIGINT:
        syslog(LOG_DEBUG ,"Caught signal SIGINT\n");
        // printf("Caught signal SIGINT\n");
        is_exec_complete = 1; 
        break;

        case SIGTERM:
        syslog(LOG_DEBUG ,"Caught signal SIGTERM\n");
        // printf("Caught signal SIGTERM\n");
        is_exec_complete = 1;
        break;

        case SIGALRM:
        syslog(LOG_DEBUG ,"Caught signal SIGALARM\n");
        is_alarm = 1;
        break;
    }

     
}

// Cleanup function to be invoked in case of SIGINT or SIGTERM
void cleanExit()
{
    int ret_status = 0;

    // Close the socket descriptor
    ret_status = close(sd);
    // Error check
    if(ERROR == ret_status){
        syslog(LOG_ERR , "Error with closing socket with errno: %d\n", errno);
    }

    // Close the file descriptor
    ret_status = close(fd);
    // Error check
    if(ERROR == ret_status){
        syslog(LOG_ERR , "Error with closing file with errno: %d\n", errno);
    }

    // Unlink the file
    ret_status = unlink(file_path);
    // Error check
    if(ERROR == ret_status){
        syslog(LOG_ERR , "Error with unlinking file with errno: %d\n", errno);
    }

    // Destroy the mutex
    ret_status = pthread_mutex_destroy(&mutex);
    // Error check
    if(SUCCESS != ret_status){
        syslog(LOG_ERR , "Error with destroying mutex with errno: %d\n", errno);
    }

    // Delete the timer
    ret_status = timer_delete(timer);
    // Error check
    if(ERROR == ret_status){
        syslog(LOG_ERR , "Error with deleting the timer with errno: %d\n", errno);
    }

    // Close the logging utility
    closelog();

    exit(EXIT_SUCCESS);
    
}

// Thread function
void *socketThreadfunc(void* threadparams)
{
    thread_data_t *thread_var = (thread_data_t *)threadparams;

    // Log the iP adddress 
    struct sockaddr_in * ip_client = (struct sockaddr_in *)&thread_var->client_addr;
    syslog(LOG_INFO , "Accepted connection from %s\n", inet_ntoa(ip_client->sin_addr)); 

    // Declare a static buffers: One to get data from recv() 
    char recv_buffer[BUFFER_SIZE];

    // Malloc buffer of the same size initially for sending the data over to the client and writing to teh file
    char *write_buffer = (char *)malloc(sizeof(char) * BUFFER_SIZE);
    // Error check: If malloc failed
    if (write_buffer == NULL){
        syslog(LOG_ERR , "malloc\n");
    }

    // Flag to check if \n was received
    uint8_t newline_flag = 0;
    int byte_count;
    int datapacket = 0;
    int final_size = 1;
    int realloc_int = 0;
    int file_size = 0;


    // Keep fetching data till there is new line is encountered
    while(!newline_flag){
        byte_count = recv(thread_var->conn_fd , recv_buffer , BUFFER_SIZE , 0);
        if (ERROR == byte_count){
            syslog(LOG_ERR , "recv\n");
            newline_flag = 1;
            // Free the buffer used
            free(write_buffer);
            // Mark as completed to move to the next 
            thread_var->is_complete = 1;
            // Close this connection
            close(thread_var->conn_fd);
        }
        else{
            final_size++;
            for(datapacket = 0; datapacket < BUFFER_SIZE; datapacket++){
                if(recv_buffer[datapacket] == '\n'){
                    newline_flag = 1;
                    break;
                }
            }

            memcpy((write_buffer + (BUFFER_SIZE * realloc_int)) , recv_buffer , BUFFER_SIZE);

            if(!newline_flag){
                write_buffer = (char *)realloc(write_buffer , (sizeof(char) * (BUFFER_SIZE * final_size)));
                // If realloc fails
                if (write_buffer == NULL){
                    syslog(LOG_ERR , "realloc\n");
                }
                else{
                    realloc_int++;
                }                    
            }
        }
    }

    if(newline_flag){
        // Reset the flag
        newline_flag = 0;

        // Now the data packet is acquired

        // Acquire the lock to write to the file
        int ret_status = pthread_mutex_lock(&mutex);
        // Error check
        if (ERROR == ret_status){
            syslog(LOG_ERR , "mutex lock\n");
        }

        // Write the data packet to the file
        int buffer_len = ((datapacket + 1) + (BUFFER_SIZE * realloc_int));
        int write_len = write(fd , write_buffer , buffer_len);
        // Error check
        if(ERROR == write_len){
            syslog(LOG_ERR , "write\n");
        }

        file_size += write_len;

        // Reset the reallocation tracking flag and the final size tracking flag
        realloc_int = 0, final_size = 1;

        // file_size += 40;
        // Allocate memory for the send buffer
        char *send_buffer = (char *)malloc(sizeof(char) * file_size);

        // Error check
        if(send_buffer == NULL){
            syslog(LOG_ERR , "malloc\n");
        }

        // Go to the beginning of the file using lseek
        off_t seek_status = lseek(fd , 0 , SEEK_SET);
        // Error check
        if(seek_status == -1){
            syslog(LOG_ERR , "lseek\n");
        }

        ssize_t bytes_read;
        int bytes_sent;

        while ((bytes_read = read(fd, send_buffer, sizeof(send_buffer))) > 0) {
            // bytes_sent is return value from send function
            bytes_sent = send(thread_var->conn_fd, send_buffer, bytes_read, 0);

            // Breaking out of loop and cleaning up if error in sending 
            if (bytes_sent == -1) {
                syslog(LOG_ERR, "Error in send; errno is %d\n", errno);
                break;
            }
        }

        // Free the send buffer
        free(send_buffer);

        // Release the lock
        ret_status = pthread_mutex_unlock(&mutex);
        // Error chekc
        if (ERROR == ret_status){
            syslog(LOG_ERR , "mutex unlock\n");
        }

    }
    // Free the buffer used
    free(write_buffer);

    // Set the flag to indicate the thread function is complete
    thread_var->is_complete = true;

    // CLose the connection
    int ret_status = close(thread_var->conn_fd);
    // Error check
    if(ERROR == ret_status){
        syslog(LOG_ERR , "close\n");
    }

    syslog(LOG_DEBUG , "Closed connection from %s\n", inet_ntoa(ip_client->sin_addr));

    return NULL;
}


int main(int argc , char *argv[])
{
    openlog(NULL , 0 , LOG_USER);

    // Register the signals 
    signal(SIGINT , signalHandler);
    signal(SIGTERM , signalHandler);
    signal(SIGALRM , signalHandler);

    // Flag to track the if daemon is to be created
    uint8_t daemon_flag = 0;

    // Check if the -d argument was passed
    char *daemon_arg = argv[1];
    if(daemon_arg != NULL){
        if (strcmp(daemon_arg , "-d") == 0){
        daemon_flag = 1;
        }
        else{
            printf("Please enter the correct argument '-d' for creating the daemon\n");
            daemon_flag = 0;
        }
    }
    

    // Variable to store the return status
    int ret_status = 0;
    struct addrinfo *servinfo;
    struct addrinfo hints;

    // File to write the data from the socket
    fd = open(file_path , O_RDWR | O_CREAT | O_TRUNC, S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP | S_IROTH);
    // Error check
    if (ERROR == fd ){
        syslog(LOG_ERR , "open\n");
        return -1;
    }

    printf("Socket Application started\n");

    // Variable to use for reusing the port logic
    int check_port_status = 1;

    // The structure has to empty initially
    memset(&hints, 0, sizeof(hints));

    // Set the attributes of the hints variable
    hints.ai_family = AF_INET;     // IPv4 type of connection
    hints.ai_socktype = SOCK_STREAM; // TCP stream sockets
    hints.ai_flags = AI_PASSIVE;     // Fill in the IP
 

    // Get the addrinfo structure for the port 9000
    if ((ret_status = getaddrinfo(NULL, PORT_NUMBER, &hints, &servinfo)) != 0) {
        syslog(LOG_ERR , "getaddrinfo\n");
        return -1;
    }

    // Get the socket descriptor
    sd = socket(servinfo->ai_family , servinfo->ai_socktype , servinfo->ai_protocol);
    // Error check
    if(ERROR == sd){
        syslog(LOG_ERR , "socket\n");
        return -1;
    }

    ret_status = setsockopt(sd , SOL_SOCKET , SO_REUSEADDR , &check_port_status , sizeof(check_port_status));
    // Error check
    if (ERROR == ret_status){
        syslog(LOG_ERR , "setsocketopt\n");
        return -1;
    }

    // Bind the socket to the local port; make it non-blocking
    // Reference: https://jameshfisher.com/2017/04/05/set_socket_nonblocking/#:~:text=To%20mark%20a%20socket%20as,Here's%20a%20complete%20example.
    int flags = fcntl(sd, F_GETFL);
    fcntl(sd, F_SETFL, flags | O_NONBLOCK);
    ret_status = bind(sd , servinfo->ai_addr , servinfo->ai_addrlen);
    // Error check
    if (ERROR == ret_status){
        syslog(LOG_ERR , "bind\n");
        printf("Fails: %d\n", errno);
        return -1;
    }

    // Before listening for a new connection, after binding to port 9000, check if daemon is to be created
    if (daemon_flag){
        ret_status = createDaemon();

        if (ERROR == ret_status){
            syslog(LOG_ERR , "createDaemon\n");
        }
        else{
            syslog(LOG_DEBUG , "Daemon created suceesfully\n");
        }
    }

    // Listen to a new connection
    ret_status = listen(sd , BACKLOG);
    if (ERROR == ret_status){
        perror("listen");
        return -1;
    }
    
    freeaddrinfo(servinfo);

    struct sockaddr client_addr;
    socklen_t addr_size = sizeof(client_addr);

    // Starting timer
    createTimer();

    // Initialize the mutex
    pthread_mutex_init(&mutex, NULL);

    // Create head, current and previous nodes for linked list
    node_t *head = NULL;
    node_t *current, *previous;

    // Loop until complete_execution flag is set
    while(!is_exec_complete) {

        if(is_alarm){
            is_alarm = 0;
            logTimestamp();
        }

        // Continuously restarting connections in the while(1) loop
        int new_fd = accept(sd, (struct sockaddr *)&client_addr, &addr_size);

        // Error check
        if (ERROR == new_fd) {
            if (errno == EWOULDBLOCK) {
                
                continue;
            }
            syslog(LOG_ERR , "accept\n");   
            continue;
        }

        // Malloc new node
        node_t *new_node = (node_t *)malloc(sizeof(node_t));
        // Error check
        if (new_node == NULL){
            syslog(LOG_ERR , "malloc\n");
            return ERROR;
        }

        // Initialize and add values of the attributes to the new node
        new_node->thread_data.is_complete = 0;
        new_node->thread_data.conn_fd = new_fd;
        new_node->thread_data.client_addr = (struct sockaddr_in *)&client_addr;

        // Spawn a new thread to handle the new connection and write the data from that connection
        ret_status = pthread_create(&(new_node->thread_data.tid), NULL, socketThreadfunc, &(new_node->thread_data));
        // Error check
        if(ret_status != SUCCESS){
            syslog(LOG_ERR , "pthread_create\n");
            printf("Error in pthread_create with err number: %d", errno);
        } 

        // Add the new node to the head of the linked list
        addFirst(&head, new_node); 
    }
    // Iterating logic to remove from linked list
    current = head;
    previous = head;

    while(current != NULL) {
        // When the node is done executing and is the head
        if ((current->thread_data.is_complete == true) && (current == head)) {
            head = current->next;
            current->next = NULL;
            pthread_join(current->thread_data.tid, NULL);
            free(current);
            current = head;
        }
        // When the node is done executing and is not the head
        else if ((current->thread_data.is_complete == 1) && (current != head)) {
            previous->next = current->next;
            current->next = NULL;
            pthread_join(current->thread_data.tid, NULL);
            free(current);
            current = previous->next;
        } 
        else {
            // Traverse the linked list till the last node is reached
            previous = current;
            current = current->next;
        }
    }
    
    printf("Socket Application completed\n");
    cleanExit();

    return 0;
}
