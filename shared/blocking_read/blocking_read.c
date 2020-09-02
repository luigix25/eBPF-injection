// #define _GNU_SOURCE
// #include <unistd.h>
// #include <string.h>
// #include <sys/syscall.h>
// #include <stdlib.h>
// #include <stdio.h>
// #include <sys/stat.h>
// #include <fcntl.h>
// #include <linux/bpf.h>
// #include <linux/version.h>
// #include <linux/perf_event.h>
// #include <linux/hw_breakpoint.h>
// #include <errno.h>
// #include <sys/ioctl.h>
// #include <unistd.h>
// #include <linux/bpf.h>
// // #include <bpf/bpf.h>
// // #include "bpf_load.h"

// #include <poll.h>
// #include <netinet/in.h> 
// #include <sys/types.h>          /* See NOTES */
// #include <sys/socket.h>
// #include <linux/netlink.h>

// #define MY_GROUP 1
// #define MAX_PAYLOAD 1024

// // int saveToFile(const char*, void*, unsigned int);

// // int saveToFile(const char* path, void* buf, unsigned int len){
// // 	FILE *f;
// // 	f = fopen(path, "w");
// // 	if(f == NULL){
// // 		printf("saveToFile: WRONG FOPEN\n");
// // 		return 1;
// // 	}

// // 	if(fwrite(buf, 1, len, f) != len){
// // 		printf("saveToFile: WRONG FWRITE\n");
// // 		return 1;
// // 	}

// // 	if(fclose(f) != 0){
// // 		printf("saveToFile: WRONG FCLOSE\n");
// // 		return 1;
// // 	}

// // 	return 0;
// // }
// int make_socket (uint16_t port){
//   int sock;
//   struct sockaddr_in name;

//   /* Create the socket. */
//   sock = socket (PF_INET, SOCK_STREAM, 0);
//   if (sock < 0)
//     {
//       perror ("socket");
//       return -1;
//     }

//   /* Give the socket a name. */
//   name.sin_family = AF_INET;
//   name.sin_port = htons (port);
//   name.sin_addr.s_addr = htonl (INADDR_ANY);
//   if (bind (sock, (struct sockaddr *) &name, sizeof (name)) < 0)
//     {
//       perror ("bind");
//       return -1;
//     }

//   return sock;
// }

// void user_receive_nl_msg(void){
//     int sock_fd;
//     struct sockaddr_nl user_sockaddr;
//     struct nlmsghdr *nl_msghdr;
//     struct msghdr msghdr;
//     struct iovec iov;

//     char* kernel_msg;

//     sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USERSOCK);
//     if(sock_fd<0)
//     {
//         printf("Error creating socket because: %s\n", strerror(errno));
//         return;
//     }


//     memset(&user_sockaddr, 0, sizeof(user_sockaddr));
//     user_sockaddr.nl_family = AF_NETLINK;
//     user_sockaddr.nl_pid = getpid();
//     user_sockaddr.nl_groups = MY_GROUP;

//     bind(sock_fd, (struct sockaddr*)&user_sockaddr, sizeof(user_sockaddr));
//     while (1) {
//         nl_msghdr = (struct nlmsghdr*) malloc(NLMSG_SPACE(1024));
//         memset(nl_msghdr, 0, NLMSG_SPACE(1024));

//         iov.iov_base = (void*) nl_msghdr;
//         iov.iov_len = NLMSG_SPACE(1024);

//         msghdr.msg_name = (void*) &user_sockaddr;
//         msghdr.msg_namelen = sizeof(user_sockaddr);
//         msghdr.msg_iov = &iov;
//         msghdr.msg_iovlen = 1;

//         printf("Waiting to receive message\n");
//         recvmsg(sock_fd, &msghdr, 0);

//         kernel_msg = (char*)NLMSG_DATA(nl_msghdr);
//         printf("Kernel message: %s\n", kernel_msg); // print to android logs
//     }

//     close(sock_fd);
// }

// int main(int ac, char **argv){
// 	char *buf;
// 	int fd;
// 	unsigned int file_len;
// 	unsigned int i;
// 	struct pollfd fds[1];
// 	int ret;
// 	int sock;
// 	int conn_sock;
	
// 	// fd = open("/dev/newdev", O_RDWR);
// 	// if (fd < 0) {
// 	//     perror("open: ");
// 	//     return 1;
// 	// }


// 	///


// 	user_receive_nl_msg();



// 	// sock = make_socket(9999);
// 	// if (sock < 0){
//  //        return -1;
//  //    } 
//  //    if (listen (sock, 1) < 0){
//  //      printf("listen error\n");
//  //      return -1;        
//  //    }
//  //    printf("waiting to accept...\n");
//  //    conn_sock = accept(sock, NULL, NULL);
//  //    printf("accepted!\n");

// 	///


// 	// if (lseek(fd, 12, SEEK_SET) < 0) {
// 	//     perror("lseek: ");
// 	//     return 1;
// 	// }

// 	// //"write" to trigger program transfer from host into the device (attached to guest)
// 	// if (write(fd, "aaa", 4) < 0) {
// 	//     perror("write: ");
// 	//     return 1;
// 	// }

// 	// //-----------------

// 	// //read length of program from device to guest userspace
// 	// if (lseek(fd, 12, SEEK_SET) < 0) {
// 	//     perror("lseek: ");
// 	//     return 1;
// 	// }

// 	// if (read(fd, &file_len, 4) < 0) {
// 	//     perror("read: ");
// 	//     return 1;
// 	// }

// 	// //printf("%u\n", file_len);
// 	// //allocate buffer + 1 for testing strings
// 	// buf = malloc(file_len + 1);

// 	// //-----------------

// 	// //read program from device to guest userspace
// 	// if (lseek(fd, 32, SEEK_SET) < 0) {
// 	//     perror("lseek: ");
// 	//     return 1;
// 	// }

// 	// for(i=0; i<file_len; i+=4){
// 	// 	if (read(fd, buf + i, 4) < 0) {
// 	// 	    perror("read: ");
// 	// 	    return 1;
// 	// 	}
// 	// }

// 	// close(fd);

// 	// //STRING TESTING
// 	// //buf[file_len] = '\0';
// 	// //printf("%s\n", buf);

// 	// //
// 	// if(saveToFile("./programs/mytestprog.o", buf, file_len) > 0){
// 	// 	return 1;
// 	// }

// 	// free(buf);



// 	// //-----------------

// 	// //LOAD SUCH BPF PROGRAM
// 	// if (load_bpf_file("./programs/mytestprog.o")) {
// 	// 	//printf("%s", bpf_log_buf);
// 	// 	return 1;
// 	// }


// 	// read_trace_pipe();

// 	return 0;
// }





#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>

#include <errno.h>

// To return informations to the device and then to the host, just write to device
// in order to trigger some action on the host side

int main(void){
	char buf[4];	
	int fd = open("/dev/newdev", O_RDWR); 
	if (fd < 0) {
		perror("open: ");
	    return 1;
	}

	// if (lseek(fd, 12, SEEK_SET) < 0) {
	//     perror("lseek: ");
	//     return 1;
	// }
	printf("going to read..\n");
	if (read(fd, buf, 4) < 0) {
	    perror("read: ");
	    return 1;
	}
	printf("read completed.\n");

	// while(1){
	// 	pause();
	// 	printf("awake\n");
	// }

	return 0;
}