#include <net/sock.h>

/*
 * socket() creates an endpoint for communication and returns a descriptor.
 * 
 * The domain argument specifies a communication domain; this selects the 
 * protocol family which will be used for communication.
 * On success, a file descriptor for the new socket is returned. 
 * On error, -1 is returned, and errno is set appropriately. 
 *
 * asmlinkage long sys_socket(int domain, int type, int protocol);
 */
void sys_socket_handler(struct pt_regs *regs)
{
	int domain, type, protocol;	
	
	domain = (int)regs->di;
	type = (int)regs->si;
	protocol = (int)regs->dx;

	printk(KERN_ALERT "Progger: sys_socket %i,%i,%i\n", 
						domain, type, protocol);
}

/*
 * connect() syscall connects the socket referred to by the fd sockfd to the 
 * address specified by addr. The addrlen argument specifies the size of addr.
 * If the connection or binding succeeds, zero is returned. 
 * On error, -1 is returned, and errno is set appropriately. 
 *
 * asmlinkage long sys_connect(int sockfd, struct sockaddr __user *addr, 
 * 								int addrlen); 
 */
void sys_connect_handler(struct pt_regs *regs)
{
	int sockfd;
	struct sockaddr __user *addr;
	int addrlen;
	struct sockaddr_in  *ipv4;
	struct sockaddr_in6 *ipv6;
	unsigned long ipv4_addr;
	unsigned char *ipv6_addr;

	sockfd = (int)regs->di;
	addr = (struct sockaddr __user *)regs->si;
	addrlen = (int)regs->dx;

	if(addr->sa_family == AF_INET) {
		ipv4 = (struct sockaddr_in *)addr;
		ipv4_addr = (unsigned long)ipv4->sin_addr.s_addr;
		
		printk(KERN_ALERT "Progger: sock_connect_v4 %d,%lu,(%pI4)\n",
					sockfd, ipv4_addr, ipv4_addr);
	}
	else if(addr->sa_family == AF_INET6) {
		ipv6 = (struct sockaddr_in6 *)addr;
		ipv6_addr = (unsigned char *)ipv6->sin6_addr.s6_addr;
		
		printk(KERN_ALERT "Progger: sock_connect_v6 %d\n", sockfd);
	}
}

/*
 * send, sendto, sendmsg - send a message on a socket 
 * 
 * send() call used only when socket is in a connected state (intended 
 * 	recipient is known).
 * 
 * send(sockfd, buf, len, flags) == sendto(sockfd, buf, len, flags, NULL, 0)
 *
 * asmlinkage long sys_send(int sockfd, void __user *buf, size_t len, 
 * 							unsigned int flags);
 * asmlinkage long sys_sendto(int, void __user *, size_t, unsigned,
 * 	                                 struct sockaddr __user *, int);
 */
void sys_sendto_handler(struct pt_regs *regs, long syscall_id)
{
	int fd;
	size_t len;
	unsigned int flags;
	struct sockaddr __user *dest_addr;
	int addr_len;

	fd = (int)regs->di;
        len = (size_t)regs->dx;
        flags = (unsigned int)regs->r10;

	if (syscall_id == __NR_sendto) {
		dest_addr = NULL;
		addr_len = 0;
	}
	else {
		dest_addr = (struct sockaddr __user *)regs->r8;
		addr_len = (int)regs->r9;
	}		
}

/*
 * sendmsg() sends a message through a connection-mode or connectionless-mode 
 * socket. 
 * If the socket is connectionless-mode, the message shall be sent to the 
 * address specified by msghdr. 
 * If the socket is connection-mode, the destination address in msghdr shall be  * ignored.
 * 
 * asmlinkage long sys_sendmsg(int fd, struct user_msghdr __user *msg, 
 * 							unsigned flags);
 */
void sys_sendmsg_handler(struct pt_regs *regs, long syscall_id)
{
	int fd;
	struct user_msghdr __user *msg;
	unsigned int flags;

	fd = (int)regs->di;
	msg = (struct user_msghdr __user *)regs->dx;
	flags = (unsigned int)regs->si;
}

/*
 * accept, accept4 - accept a connection on a socket
 *
 * asmlinkage long sys_accept(int fd, struct sockaddr __user *upeer_sockddr, 
						int __user *upeer_addrlen);
 */
void sys_accept_handler(struct pt_regs *regs)
{
	int fd;
	struct sockaddr __user *upeer_sockddr;
	int __user *upeer_addrlen;

	fd = (int)regs->di;
	upeer_sockddr = (struct sockaddr __user *)regs->dx;
	upeer_addrlen = ( int __user *)regs->si;

}

/*
 * The recvfrom() function shall receive a message from a connection-mode or 
 * connectionless-mode socket. 
 * It is normally used with connectionless-mode sockets because it permits 
 * the application to retrieve the source address of received data
 * 
 * asmlinkage long sys_recvfrom(int fd, void __user *ubuf, size_t size, 
 * 				unsigned int flags, 
 *				struct sockaddr __user *addr, 
 * 				int __user *addr_len);
 */
void sys_recvfrom_handler(struct pt_regs *regs)
{
	


}

/* asmlinkage long sys_recvmsg(int fd, struct user_msghdr __user *msg, 
 * 							unsigned int flags);
 */
void sys_recvmsg_handler(struct pt_regs *regs)
{



}
