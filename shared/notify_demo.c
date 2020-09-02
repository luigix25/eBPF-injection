#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <string.h>


static void handle_events(int fd, int *wd, char* path){
    /* Some systems cannot read integer variables if they are not
    properly aligned. On other systems, incorrect alignment may
    decrease performance. Hence, the buffer used for reading from
    the inotify file descriptor should have the same alignment as
    struct inotify_event. */

    char buf[4096]
    __attribute__ ((aligned(__alignof__(struct inotify_event))));
    const struct inotify_event *event;
    ssize_t len;
    char *ptr;

    /* Loop while events can be read from inotify file descriptor. */

    for (;;) {

               /* Read some events. */

        len = read(fd, buf, sizeof buf);
        if (len == -1 && errno != EAGAIN) {
            perror("read");
            exit(EXIT_FAILURE);
        }

               /* If the nonblocking read() found no events to read, then
                  it returns -1 with errno set to EAGAIN. In that case,
                  we exit the loop. */

        if (len <= 0)
            break;

       /* Loop over all events in the buffer */

        for (ptr = buf; ptr < buf + len; ptr += sizeof(struct inotify_event) + event->len) {

            event = (const struct inotify_event *) ptr;

            /* Print event type */

            if (event->mask & IN_OPEN)
                printf("IN_OPEN: ");
            if (event->mask & IN_CLOSE_NOWRITE)
                printf("IN_CLOSE_NOWRITE: ");
            if (event->mask & IN_CLOSE_WRITE)
                printf("IN_CLOSE_WRITE: ");

            /* Print the name of the watched directory */

            if (wd[0] == event->wd) {
                printf("%s/", path);
                //break;
            }        

            /* Print the name of the file */

            if (event->len)
                printf("%s", event->name);

            /* Print type of filesystem object */

            if (event->mask & IN_ISDIR)
                printf(" [directory]\n");
            else
                printf(" [file]\n");

            fflush(stdout);

        }
    }


}


static void waitForNotification(void){
    //Check for file modification into the host to trigger some event on the guest
    char buf;
    int fd, poll_num;
    int *wd;
    nfds_t nfds;
    char path[] = "/home/giacomo/shared";
    struct pollfd fds[2];

        /* Create the file descriptor for accessing the inotify API */

    fd = inotify_init1(IN_NONBLOCK);
    if (fd == -1) {
        perror("inotify_init1");
        exit(EXIT_FAILURE);
    }

        /* Allocate memory for watch descriptors */

    wd = calloc(1, sizeof(int));
    if (wd == NULL) {
        perror("calloc");
        exit(EXIT_FAILURE);
    }

    /* Mark directories for events
        - file was opened
        - file was closed */


    wd[0] = inotify_add_watch(fd, path, IN_OPEN | IN_CLOSE);
    if (wd[0] == -1) {
        fprintf(stderr, "Cannot watch '%s': %s\n", path, strerror(errno));
        exit(EXIT_FAILURE);
    }

                   /* Prepare for polling */

    nfds = 2;

           /* Console input */

    fds[0].fd = STDIN_FILENO;
    fds[0].events = POLLIN;

           /* Inotify input */

    fds[1].fd = fd;
    fds[1].events = POLLIN;


    printf("Listening for events.\n");
    while (1) {
        poll_num = poll(fds, nfds, -1);
        if (poll_num == -1) {
            if (errno == EINTR)
                continue;
            perror("poll");
            exit(EXIT_FAILURE);
        }

        if (poll_num > 0) {
            if (fds[0].revents & POLLIN) {
                /* Console input is available. Empty stdin and quit */
                while (read(STDIN_FILENO, &buf, 1) > 0 && buf != '\n')
                    continue;
                break;
            }

            if (fds[1].revents & POLLIN) {
                /* Inotify events are available */
                handle_events(fd, wd, path);
            }
        }
    }

    printf("Listening for events stopped.\n");

    /* Close inotify file descriptor */

    close(fd);

    free(wd);


}

int main(){
    waitForNotification();
}