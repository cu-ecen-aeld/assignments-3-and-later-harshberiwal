/**
 * @file    aesdsocket.c
 *
 * @brief   A multithreaded TCP socket server.
 *
 * @author  Harinarayanan Gajapathy (haga9942@colorado.edu)
 * @date    2023-03-02
 *
 * @copyright Copyright (c) 2023 Harinarayanan Gajapathy
 * Redistribution, modification or use of this software in source or binary
 * forms is permitted as long as the files maintain this copyright. Users
 * are permitted to modify this and use it to learn about the field of
 * embedded software. Harinarayanan Gajapathy and the University of Colorado
 * are not liable for any misuse of this material
 *
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "queue.h"      /* taken from https://github.com/freebsd/freebsd-src/blob/main/sys/sys/queue.h */

// #define DEBUG    /* un-comment this line to redirect output to stdout */
#ifdef DEBUG
#define SYSLOG_OPTIONS          (LOG_PERROR | LOG_NDELAY)
#else
#define SYSLOG_OPTIONS          (LOG_NDELAY)
#endif

#define PORT_NUMBER             9000
#define MAX_BACKLOG             10
#define MAX_BUF_LEN             1024
#define FILE_MODE               0644
#define NULL_BYTE               1
#define TIMER_THREAD_PERIOD     10

#define USE_AESD_CHAR_DEVICE    1

#if (USE_AESD_CHAR_DEVICE == 1)
const char *log_file = "/dev/aesdchar";
#elif (USE_AESD_CHAR_DEVICE == 0)
const char *log_file = "/var/tmp/aesdsocketdata";
#endif

volatile sig_atomic_t caught_signal = 0;

struct node {
    pthread_t tid;
    pthread_mutex_t *mutex;
    int connfd;
    int thread_complete_success;
    SLIST_ENTRY(node) nodes;
};

/**
 * @brief Signal handler
 *
 * @param signo SIGINT or SIGTERM
 */
static void signal_handler(int signo)
{
    if (signo == SIGINT || signo == SIGTERM) {
        caught_signal = 1;
        syslog(LOG_INFO, "Caught signal, exiting");
    }
}

/**
 * @brief Write client packet to *log_file when a new '\n' line
 * character is found in client TCP stream and echo back the
 * packet to client. This function implements locking functions
 * using pthread mutex to synchronize access to *log_file.
 *
 * @param msg message from client
 * @param fd client fd to echo data
 * @return int 0 on success or -1 on failure
 */
static int process_msg(char *msg, int fd, pthread_mutex_t *mutex)
{
    int rc = 0;
    int log_file_fd, cnt;
    char *start, *end;
#if (USE_AESD_CHAR_DEVICE == 0)
    struct stat statbuf;
    off_t offset = 0;
#endif
    char buf[MAX_BUF_LEN];


    start = end = (char *) msg;

    rc = open(log_file, (O_CREAT | O_APPEND | O_RDWR), FILE_MODE);
    if (rc == -1) {
        syslog(LOG_ERR, "failed to open %s", log_file);
        return rc;
    }

    log_file_fd = rc;

    while ((end = strchr(start, '\n')) != NULL) {
        /* write packet to log file */
        cnt = 0;
        while (cnt != ((end - start) + 1)) {

            if (pthread_mutex_lock(mutex) != 0) {
                syslog(LOG_ERR, "failed to lock mutex object before writing data to file");
                goto exit;
            }

            rc = write(log_file_fd, &start[cnt], (((end - start) + 1) - cnt));

            if (pthread_mutex_unlock(mutex) != 0) {
                syslog(LOG_ERR, "failed to lock mutex object after writing data to file");
                goto exit;
            }

            if (rc == -1)
                goto exit;

            cnt += rc;
        }

#if (USE_AESD_CHAR_DEVICE == 0)
        /* read file total size, in bytes */
        rc = fstat(log_file_fd, &statbuf);
        if (rc != 0) {
            syslog(LOG_ERR, "failed to obtain information about %s", log_file);
            goto exit;
        }

        /* read file contents and send to client */
        memset(buf, 0, MAX_BUF_LEN);
        cnt = 0;
        while (cnt != statbuf.st_size) {

            rc = pread(log_file_fd, buf, MAX_BUF_LEN, offset);
            if (rc == -1)
                goto exit;

            cnt += rc;
            offset += rc;

            rc = send(fd, buf, cnt, 0);
            if (rc == -1)
                goto exit;

            memset(buf, 0, MAX_BUF_LEN);
        }
#elif (USE_AESD_CHAR_DEVICE == 1)
        memset(buf, 0, MAX_BUF_LEN);
        do {
            rc = read(log_file_fd, buf, 1);
            if (rc == -1)
                goto exit;
            if (send(fd, buf, rc, 0) == -1)
                goto exit;
        } while (rc != 0);
#endif
        start = end + 1;
    }

exit:
    close(log_file_fd);

    return (rc != -1) ? 0 : -1;
}

/**
 * @brief A thread function runs for every new incoming client
 * connection.
 *
 * @param thread_param struct node data
 * @return void* returns NULL
 */
void *thread_func(void *thread_param)
{
    int rc;
    struct node *n = NULL;
    char *msg = NULL;
    int msg_size = 0;       /* total size of *msg */
    int msg_len = 0;        /* bytes available in *msg */
    char buf[MAX_BUF_LEN] = {};

    if (thread_param == NULL)
        return NULL;

    n = (struct node *) thread_param;

    /* save every incoming data to msg buffer and search for '\n' character */
    while (((rc = recv(n->connfd, buf, MAX_BUF_LEN, 0)) > 0) && caught_signal == 0) {
        if ((msg_size - msg_len) < rc) {
            msg_size += (rc + NULL_BYTE);

            msg = (char *) realloc(msg, msg_size);
            if (msg == NULL) {
                syslog(LOG_ERR, "failed to allocate memory for msg");
                break;
            }
            memset(msg + msg_len, 0, msg_size - msg_len);
        }

        memcpy(msg + msg_len, buf, rc);
        msg_len += rc;

        if (process_msg(msg, n->connfd, n->mutex) != 0)
            break;
    }

    if (msg != NULL)
        free(msg);

    n->thread_complete_success = 1;
    close(n->connfd);

    return NULL;
}

/**
 * @brief A timerthread function logs timestamp to *log_file every
 * TIMER_THREAD_PERIOD seconds. The sleep routine is based on
 * explanation from Chapter: 11 Time.
 *
 * @param thread_param struct node data
 * @return void* returns NULL
 */
void *timer_thread_func(void *thread_param)
{
    struct node *n = NULL;
    struct tm *tmp;
    struct timespec ts;
    time_t t;
    char outstr[MAX_BUF_LEN] = {};
    int fd;

    if (thread_param == NULL)
        return NULL;

    n = (struct node *) thread_param;

    while (!caught_signal) {
        if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
            syslog(LOG_ERR, "failed to retrieve time");
            break;
        }

        ts.tv_sec += TIMER_THREAD_PERIOD;   /* 10 seconds */
        if (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL) != 0) {
            syslog(LOG_ERR, "failed to sleep");
            break;
        }

        t = time(NULL);
        if (t == ((time_t) -1)) {
            syslog(LOG_ERR, "failed to retrieve the seconds since epoch");
            break;
        }

        tmp = localtime(&t);
        if (tmp == NULL) {
            syslog(LOG_ERR, "failed to retrieve localtime");
            break;
        }

        strftime(outstr, sizeof(outstr), "timestamp: %Y, %b, %d, %H:%M:%S\n", tmp);

        fd = open(log_file, (O_CREAT | O_APPEND | O_RDWR), FILE_MODE);
        if (fd == -1) {
            syslog(LOG_ERR, "failed to open %s", log_file);
            break;
        }

        if (pthread_mutex_lock(n->mutex) != 0) {
            close(fd);
            syslog(LOG_ERR, "failed to lock mutex object before writing timestamp");
            break;
        }

        if (write(fd, outstr, strlen(outstr)) == -1)
            syslog(LOG_ERR, "failed to write timestamp to %s", log_file);

        if (pthread_mutex_unlock(n->mutex) != 0) {
            close(fd);
            syslog(LOG_ERR, "failed to unlock mutex object after writing timestamp");
            break;
        }

        close(fd);
    }

    /* we set this flag to make the parent process to join the thread */
    n->thread_complete_success = 1;

    return NULL;
}

/**
 * @brief Create a listener socket object.
 *
 * @param sock file descriptor of listenting socket
 * @param portnum port number to bind
 * @return int 0 on success or -1 on failure
 */
static int create_listener_socket(int *sock, int portnum)
{
    int optval = 1;
    struct sockaddr_in sa;

    if ((*sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        syslog(LOG_ERR, "failed to create a socket: %s", strerror(errno));
        return -1;
    }

    if (setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) != 0) {
        syslog(LOG_ERR, "failed to set socket options: %s", strerror(errno));
        return -1;
    }

    bzero((char *)&sa, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = htons((unsigned short) portnum);
    if (bind(*sock, (struct sockaddr *) &sa, sizeof(sa)) != 0) {
        syslog(LOG_ERR, "failed to bind socket to port %d: %s", PORT_NUMBER, strerror(errno));
        return -1;
    }

    if (listen(*sock, MAX_BACKLOG) != 0) {
        syslog(LOG_ERR, "failed to mark socket %d as passive: %s", *sock, strerror(errno));
        return -1;
    }

    return 0;
}

/**
 * @brief Initialize & setup resources required to run a simple TCP
 * socket server with multi-threaded support.
 *
 * @param mode 0 - normal process or 1 - daemon
 * @return int 0 on success or -1 on failure
 */
static int aesdsocket(int *mode)
{
    int rc = -1;
    int socket, newfd = -1;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    struct node *n = NULL;
    struct node *n_tmp = NULL;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

    /* init linked-list */
    SLIST_HEAD(head_s, node) head;
    SLIST_INIT(&head);

    rc = create_listener_socket(&socket, PORT_NUMBER);
    if (rc == -1)
        goto error;

    if (*mode)
        daemon(0, 0);

#if (USE_AESD_CHAR_DEVICE == 0)
    /* timer thread to write timestamp to *log_file */
    n = (struct node *) calloc(1, sizeof(struct node));
    if (n == NULL) {
        syslog(LOG_ERR, "failed to allocate memory for timer node: %s", strerror(errno));
        rc = -1;
        goto error;
    }
    n->mutex = &mutex;
    n->thread_complete_success = 0;
    rc = pthread_create(&n->tid, NULL, timer_thread_func, n);
    if (rc != 0) {
        syslog(LOG_ERR, "failed to create timer thread: %s", strerror(errno));
        goto error;
    }
    SLIST_INSERT_HEAD(&head, n, nodes);
#endif

    while (!caught_signal) {
        newfd = accept(socket, (struct sockaddr *) &addr, &addrlen);
        if (newfd == -1) {
            rc = -1;
            goto reap_threads;
        }

        syslog(LOG_INFO, "Accepted connection from %s", inet_ntoa(addr.sin_addr));

        /* thread per client connection */
        n = (struct node *) calloc(1, sizeof(struct node));
        if (n == NULL) {
            syslog(LOG_ERR, "failed to allocate memory for client node: %s", strerror(errno));
            rc = -1;
            goto error;
        }
        n->connfd = newfd;
        n->mutex = &mutex;
        n->thread_complete_success = 0;
        rc = pthread_create(&n->tid, NULL, thread_func, n);
        if (rc != 0) {
            syslog(LOG_ERR, "failed to create client thread: %s", strerror(errno));
            goto error;
        }
        SLIST_INSERT_HEAD(&head, n, nodes);

reap_threads:
        /* remove all thread from linked-list, if threads have completed execution */
        n = NULL;
        SLIST_FOREACH_SAFE(n, &head, nodes, n_tmp) {
            if (n->thread_complete_success) {
                pthread_join(n->tid, NULL);
                SLIST_REMOVE(&head, n, node, nodes);
                free(n);
            }
        }
    }

error:
    if (socket != -1) {
        shutdown(socket, SHUT_RDWR);
        close(socket);
    }

    /* delete linked-list */
    n = NULL;
    while (!SLIST_EMPTY(&head)) {
        n = SLIST_FIRST(&head);
        SLIST_REMOVE_HEAD(&head, nodes);
        free(n);
    }
    SLIST_INIT(&head);

    pthread_mutex_destroy(&mutex);

    return rc;
}

/**
 * @brief       main function
 *
 * @param argc  argument count
 * @param argv  argument values as vector
 * @return int  0 on success or -1 on failure
 */
int main(int argc, char *argv[])
{
    int rc, opt;
    int run_as_daemon = 0;
    struct sigaction sa;

    openlog(NULL, SYSLOG_OPTIONS, LOG_USER);

    /* parse command-line arguments */
    while ((opt = getopt(argc, argv, "d")) != -1) {
        switch (opt) {
        case 'd':
            run_as_daemon = 1;
            syslog(LOG_INFO, "running %s in daemon mode", argv[0]);
            break;
        }
    }

    /* set-up signal handler for SIGINT & SIGTERM */
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = signal_handler;

    rc = sigaction(SIGINT, &sa, NULL);
    if (rc != 0) {
        syslog(LOG_ERR, "failed to setup signal handler for SIGINT");
        goto exit;
    }

    rc = sigaction(SIGTERM, &sa, NULL);
    if (rc != 0) {
        syslog(LOG_ERR, "failed to setup signal handler for SIGTERM");
        goto exit;
    }

    /* we are all set to run aesdsocket server */
    rc = aesdsocket(&run_as_daemon);

exit:
    syslog(LOG_INFO, "Exiting aesdsocket!");
    remove(log_file);
    closelog();

    return rc;
}
