#include <linux/slab.h>
#include <linux/crc32.h>
#include <net/inet_common.h>
#include <linux/tty.h>

#include "./proggerConfig.h"
//#include "common.h"		/* TJ for compiling strlen_user 4, April, 2018 */
#include "definitions.h"	/* TJ to seperate codes according to defines.  April, 2018 */
#include "progger_utils.h"	/* TJ to define STR_IN_USERAREA.  April, 2018 */
#include "log.h"			/* TJ for log messages  April, 2018 */

struct process_info {
	kuid_t uid;
	long pid;
	char *proc_name;
};

struct node_regs {
        struct pt_regs regs;
	struct timespec ts;
	struct process_info proc_info;
        struct node_regs *next;
};

struct q_regs {
        struct node_regs *first, *last;
	int size;
};

uint64_t to_nanoseconds(struct timespec ts) {
    return ts.tv_sec * (uint64_t)1000000000L + ts.tv_nsec;
}

uint64_t timespec_diff(struct timespec start, struct timespec curr)
{
	return (to_nanoseconds(curr) - to_nanoseconds(start));
}

unsigned long get_inode(long fd)
{
	struct file *current_file;
	unsigned long inode_num;

	rcu_read_lock();
                current_file = fcheck(fd);
                if (current_file)
                        inode_num = current_file->f_inode->i_ino;
                else {
			inode_num = -1;
		}
        rcu_read_unlock();

	return inode_num;
}

bool init_socket(struct socket **sock )
{
        struct sockaddr_in *dest_addr;
	int ret;
	
	printk(KERN_ALERT "Progger: init_socket/ started\n");

        dest_addr = (struct sockaddr_in *)kmalloc(sizeof(struct sockaddr_in),
                                                                GFP_KERNEL);

        WARN_ON(!dest_addr);

        *sock = (struct socket *)kmalloc(sizeof(struct socket), GFP_KERNEL);
        if (!*sock) {
                printk(KERN_ALERT "Progger: init_socket/sock is null \n");
                return false;
        }

        if (sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, sock) < 0) {
                printk(KERN_ALERT
                        "Progger: init_socket/Error creating TCP socket\n");
                return false;
        }

        memset(dest_addr, 0, sizeof(struct sockaddr_in));
        dest_addr->sin_family = AF_INET;
        dest_addr->sin_addr.s_addr = htonl(REDIS_ADDR);
        dest_addr->sin_port = htons(REDIS_PORT);

        ret = inet_stream_connect(*sock, (struct sockaddr *) dest_addr,
        				sizeof(struct sockaddr_in), 0);
	if (ret <0) {
		printk(KERN_ALERT "Progger: init_socket/Error binding socket, %i\n", ret);
		return false;
	}
	return true;
}

void write_to_tty(char *string)
{
	struct tty_struct *tty;

	tty = get_current_tty();

	if (tty != NULL) 
        	(tty->driver->ops->write) (tty, string, strlen(string));
    	else
        	printk("tty equals to zero");
}

int is_socket(struct files_struct *files, int fd)
{
       struct file *file;

       if (files == NULL)
                printk(KERN_ALERT "Progger: ERROR files_struct\n");

        rcu_read_lock();
        /* Check whether the specified fd has an open file */
        file = fcheck_files(files, fd);
        if (file != NULL) {
                /* if the fd is a socket fd */
                if(((file->f_path.dentry->d_inode->i_mode) & S_IFMT)
                                                        == S_IFSOCK) {
                        rcu_read_unlock();
                        return 1;
                }
                else {
                        rcu_read_unlock();
                        return 0;
                }
        }
        rcu_read_unlock();
        return -2;
}

#ifdef ABSENCE_STRLEN_USER
STR_IN_USERAREA* stUstr_to_kspace(const char __user *u_str)
{
	STR_IN_USERAREA* stKstr = NULL;

	stKstr = kmalloc(sizeof(STR_IN_USERAREA), GFP_KERNEL);
	if(stKstr == NULL){
		printk(KERN_ALERT "Progger: ERROR allocating memory\n");
		return NULL;
	}

	stKstr->user_str=NULL;
	stKstr->user_str_len=0;

    /* Allocate space in memory for kernelspace string */
    stKstr->user_str = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
    if (stKstr->user_str==NULL){
		printk(KERN_ALERT "Progger: ERROR allocating memory\n");
		kfree(stKstr);
		return NULL;
	}

    memset(stKstr->user_str, 0, PATH_MAX);

    stKstr->user_str_len = strncpy_from_user(stKstr->user_str, u_str, PATH_MAX);
    if(stKstr->user_str_len == EFAULT){
    	printk(KERN_ALERT "Progger: access to userspace fails\n");
    	kfree(stKstr->user_str);
    	kfree(stKstr);
    	return NULL;
    }
    else if(stKstr->user_str_len == PATH_MAX){
    	stKstr->user_str[PATH_MAX-1] = NULL;
    }

    LOG_STR_USER(stKstr->user_str, stKstr->user_str_len);
    //printk(KERN_ALERT "Progger: %s %d\n", stKstr->user_str, stKstr->user_str_len);
    return stKstr;
}

#else

char *ustr_to_kspace(const char __user *u_str)
{
	long str_len = 10;
	char *k_str = NULL;

	/* Get length of null-terminated userspace string */
	str_len = strlen_user(u_str);

/* TJ for using strncpy_from_user instead of strlen_user
 * because of absence of strlen_user after kernel version 4.13.1
 * date: 10, April, 2018 */
	if(str_len==0){
		printk(KERN_ALERT "Progger: ERROR reading string in user space\n");
		return NULL;
	}
    /* Allocate space in memory for kernelspace string */
    k_str = (char *)kmalloc(str_len, GFP_KERNEL);

	if (k_str==NULL) {
		printk(KERN_ALERT "Progger: ERROR allocating k_str\n");
		return NULL;
	}
    /* Convert userspace strings to kernelspace */
    strncpy_from_user(k_str, u_str, str_len);

	return k_str;
}
#endif

/*
 * Function that compares the values in the registers in struct pt_regs
 */
bool compare_ptregs(struct pt_regs *a, struct pt_regs b)
{
	return (a->di == b.di 
		&& a->si == b.si
		&& a->dx == b.dx);
}

/* Implementation of a queue using linked lists */
struct q_regs *create_queue(void)
{
	struct q_regs *q = 
		(struct q_regs *)kmalloc(sizeof(struct q_regs), GFP_KERNEL);
	
	if (!q) {
		printk(KERN_ALERT 
			"Progger: QQ ERROR couldn't kmalloc struct q_regs q\n");
		return NULL;
	}
	/* empty q, so first and last nodes are null */
	q->first = q->last = NULL;
	q->size = 0;	

	return q;
}
struct node_regs *new_node(struct pt_regs *regs, struct timespec ts,
						struct process_info proc_info)
{
	struct node_regs *tmp = 
		(struct node_regs *)kmalloc(sizeof(struct node_regs), GFP_KERNEL);
	if (!tmp)
		return NULL;

	tmp->regs.di = (long)regs->di;
	tmp->regs.dx = (long)regs->dx;
	tmp->regs.si = (long)regs->si;

	tmp->ts = ts;
	tmp->proc_info = proc_info;

	tmp->next = NULL;

	return tmp;
}
int enqueue(struct q_regs *q, struct pt_regs *regs, 
			struct process_info proc_info, struct timespec ts)
{
	struct node_regs *tmp = new_node(regs, ts, proc_info);
	
	if (tmp == NULL){
		printk(KERN_ALERT "Progger: QQ ERROR new node NULL\n");
		return 0;
	}

	q->size++;

	/* if the queue is empty, the new node is both first and last */ 
	if (q->last == NULL) {
		q->first = q->last = tmp;
		return 1;
	}
	
	/* add new node at end of queue and update the last node */
	q->last->next = tmp;
	q->last = tmp;

	return 1;
}

struct node_regs *found_node(struct q_regs *q, struct pt_regs *regs_to_find)
{
	struct node_regs *current_node;
	struct node_regs *prev_node;
	struct node_regs *tmp;
	struct timespec ts;

	/* q is empty */
	if (q->last == NULL || q->first == NULL) {
		return NULL;
	//	return (struct timespec){.tv_sec = 0, .tv_nsec = 0};
	}

	/* first node is a match */
	if (compare_ptregs(regs_to_find, q->first->regs)) {
		q->size--;
		tmp = q->first;
		ts = tmp->ts;
	
		/* if there is only 1 item in the q */
		if (q->first == q->last)
			q->first = q->last = NULL; 
		/* set the new q->first as the second item in the Q */
		else {	
			q->first = q->first->next;
		}

		/* get rid of the previous first node, i.e. tmp */
	//	WARN_ON(!tmp);
	//	kfree(tmp);

		return tmp;
	}

	/* loop through q items to find regs_to_find, starting with 2nd node */
	prev_node = q->first;
	current_node = q->first->next;
	while (current_node != NULL) {
		/* if regs_to_find is found in Q */
		if (compare_ptregs(regs_to_find, current_node->regs)) {
			q->size--;
			if (prev_node == NULL) {
				return NULL;
			//return (struct timespec){.tv_sec = 0, .tv_nsec = 0};
			}
			
			/* last node is a match */
			if (current_node == q->last) {
				q->last = prev_node;
				q->last->next = NULL;			
			}
			else {
				// update current's prev node's next pointer 
				prev_node->next = current_node->next;
			}

			ts = current_node->ts;
			/* free pointer to the current matched node */
			WARN_ON(!current_node);
			kfree(current_node);
			
			return current_node;
		}
		// match not found, move on to next node 
		prev_node = current_node;
		current_node = current_node->next;
	}	
	return NULL;
//	return (struct timespec){.tv_sec = 0, .tv_nsec = 0};	
}

struct timespec get_current_time(void)
{
	struct timespec ts;
	getnstimeofday(&ts);

	return ts;
}
