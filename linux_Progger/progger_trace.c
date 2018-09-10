#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/version.h>
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 20)		/* 30 May TJChoi : have to find the reason of #if */
#include <linux/kobject.h>
#include <trace/sched.h>
#include "ppm_syscall.h"
#include <trace/syscall.h>
#else
#include <asm/syscall.h>
#endif
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 37))		/* 30 May TJChoi : have to find the reason of #if */
#include <asm/atomic.h>
#else
#include <linux/atomic.h>
#endif
#include <linux/cdev.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kdev_t.h>
#include <linux/fs_struct.h>
#include <linux/delay.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>
#include <linux/fdtable.h>
#include <linux/wait.h>
#include <linux/uaccess.h>
#include <linux/tracepoint.h>
#include <linux/cpu.h>
#include <linux/jiffies.h>
#include <linux/cred.h>
#include <net/sock.h>
#include <asm/asm-offsets.h>	/* For NR_syscalls */
#include <asm/unistd.h>
#include <linux/unistd.h>
#include <linux/sysctl.h>
#include <linux/utsname.h>

#include "./progger_driver_config.h"
#include "./syscall_defs.h"

#include "./progger_utils.c"
#include "./file_syscalls.c"
#include "./socket_syscalls.c"
#ifdef MODULE_PARAM										/* 12 June TJChoi : for module param */
#include "definitions.h"
#include <linux/init.h>
#include "log.h"										/* 14 June TJChoi : for HostId */
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Meena Mungro, Cyber Security Lab, University of Waikato");

#ifdef MODULE_PARAM										/* 12 June TJChoi : for module param */
//typedef unsigned long long progger_uint64;
static char*	cpHostId=NULL;
module_param(cpHostId, charp, 0);
MODULE_PARM_DESC(cpHostId, "this is the string pointer of mac address");
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35))								/* 30 May TJChoi : have to find the reason of #if */
    #define TRACEPOINT_PROBE_REGISTER(p1, p2) tracepoint_probe_register(p1, p2)
    #define TRACEPOINT_PROBE_UNREGISTER(p1, p2) tracepoint_probe_unregister(p1, p2)
    #define TRACEPOINT_PROBE(probe, args...) static void probe(args)
#else
    #define TRACEPOINT_PROBE_REGISTER(p1, p2) tracepoint_probe_register(p1, p2, NULL)
    #define TRACEPOINT_PROBE_UNREGISTER(p1, p2) tracepoint_probe_unregister(p1, p2, NULL)
    #define TRACEPOINT_PROBE(probe, args...) static void probe(void *__data, args)
#endif

#ifndef CONFIG_HAVE_SYSCALL_TRACEPOINTS
 #error The kernel must have HAVE_SYSCALL_TRACEPOINTS in order for Progger to be useful
#endif

TRACEPOINT_PROBE(syscall_enter_probe, struct pt_regs *regs, long id);
TRACEPOINT_PROBE(syscall_exit_probe, struct pt_regs *regs, long ret);

/*
 * GLOBALS
 */
/*static bool g_tracepoint_registered; TJCHOI */
static bool g_tracepoint_registered=false;

struct q_regs *q_opened = NULL;										/* 30 May TJChoi : added initial value as NULL */
static bool record_open_regs;
static const int NO_OPEN_RETVAL = -1;
struct node_regs;
struct q_regs;

static DEFINE_MUTEX(progger_mutex);

bool socket_initialised;
struct socket *sock = NULL;

static int count_enter[__NR_mlock2] = {0};

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)					/* 30 May TJChoi : have to find the reason of #if */
static struct tracepoint *tp_sys_enter;
static struct tracepoint *tp_sys_exit;
#else
struct class_device *g_ppe_dev = NULL;								/* 30 May TJChoi : have to add codes for g_ppe_dev */
#endif


/* compat tracepoint functions */
static int compat_register_trace(void *func, const char *probename, struct tracepoint *tp)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0))					/* 30 May TJChoi : have to find the reason of #if */
	return TRACEPOINT_PROBE_REGISTER(probename, func);
#else
	return tracepoint_probe_register(tp, func, NULL);
#endif
}

static void compat_unregister_trace(void *func, const char *probename, struct tracepoint *tp)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0))					/* 30 May TJChoi : have to find the reason of #if */
	TRACEPOINT_PROBE_UNREGISTER(probename, func);
#else
	tracepoint_probe_unregister(tp, func, NULL);
#endif
}

static void visit_tracepoint(struct tracepoint *tp, void *priv)		/* 31 May TJChoi : have to find the usage of priv */
{
	if (!strcmp(tp->name, "sys_enter"))								/* 31 May TJChoi : to avoid the system already has its sys_enter */
		tp_sys_enter = tp;											/* 31 May TJChoi : to get tp list from sys_enter. */
	else if (!strcmp(tp->name, "sys_exit"))
		tp_sys_exit = tp;
}

static int get_tracepoint_handles(void)
{
	for_each_kernel_tracepoint(visit_tracepoint, NULL);				/* 31 May TJChoi : need to find the use case of this function */
	if (!tp_sys_enter) {
		return -ENOENT;
	}
	if (!tp_sys_exit) {
		return -ENOENT;
	}
	return 1;
}

int init_module(void)
{
	int ret = -1;
	
	record_open_regs = true;
	dHostId = 0;										/* 14 June TJChoi : for HostId */

	printk(KERN_ALERT "Progger: module insertion started\n");

	q_opened = create_queue();										/* 31 May TJChoi : why we need to create queue, just following sysdig? */
	if (q_opened == NULL) {
		printk(KERN_ALERT 
			"Progger: error creating q_opened, handling Open syscalls without a return value!\n");
		record_open_regs = false;		
	}

	ret = get_tracepoint_handles();

	if (ret < 0)
	{
		printk(KERN_ALERT "Progger: couldn't get tracepoint handles\n");
		goto err_sys_enter;											/* 31 May TJChoi : add this for error situation like sysdig */
	}

	if (!g_tracepoint_registered) {

		printk(KERN_ALERT "Progger: tracepoint registration started\n");

#if 0									/* 31 May TJChoi : duplicated checking routine with 'get_tracepoint_handles();' */
		if (tp_sys_exit == NULL)
			printk(KERN_ALERT "Progger: sys_exit null\n");
#endif

		/* Enable sys_exit tracepoint */
		#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)					/* 30 May TJChoi : have to find the reason of #if */
			ret = compat_register_trace(syscall_exit_probe, 
							"sys_exit", 
							tp_sys_exit);
		#else
			ret = register_trace_syscall_enter(syscall_exit_probe);			/* 31 May TJChoi : org syscall_enter_probe, but it looked wrong  */
		#endif
		if (ret) { 															/* 31 May TJChoi : add this for error situation like sysdig */
			printk(KERN_ALERT 
				"Progger: can't create sys_exit tracepoint\n");
			goto err_sys_enter;
			return;
		}

		printk(KERN_ALERT "Progger: success create sys_exit tp \n");

		/* Enable sys_enter tracepoint */
		#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)					/* 30 May TJChoi : have to find the reason of #if */
			ret = compat_register_trace(syscall_enter_probe, 
							"sys_enter", 
							tp_sys_enter);
		#else
			ret = register_trace_syscall_exit(syscall_enter_probe);			/* 31 May TJChoi : org syscall_exit_probe, but it looked wrong  */
		#endif
		if (ret) {
			printk(KERN_ALERT 
			"Progger: can't create the sys_enter tracepoint\n");
			goto err_sys_enter;
		}
                printk(KERN_ALERT "Progger: success create sys_enter tp \n");

		g_tracepoint_registered = true;
	}
#if 1
	/* Setup socket for sending TCP packets to the Redis server */
	mutex_lock(&progger_mutex);
	socket_initialised = init_socket(&sock);
	if (!socket_initialised) {

		write_to_tty("\nProgger:ERROR-couldn't create TCP socket\n\n");
		sock = NULL;
		mutex_unlock(&progger_mutex);										/* 31 May TJChoi : add this for error situation like sysdig */
		goto err_sys_enter;													/* 31 May TJChoi : add this for error situation like sysdig */
	}
	else
		write_to_tty("\nProgger: TCP socket created successfully\n");
	
        mutex_unlock(&progger_mutex);
#endif
    printk(KERN_ALERT "Progger: mac=%s\n", cpHostId);
	{
		char cptemp[32]="\0";
		int ilength_Hostid = strlen(cpHostId);

		if(ilength_Hostid>32)
			goto err_sys_enter;
		strncpy(&cptemp[1], cpHostId, ilength_Hostid);
		cptemp[0]='+';
		cptemp[ilength_Hostid+1]='\n';
		if(kstrtoull(cptemp, 16, &dHostId)!=0)
			goto err_sys_enter;
		printk(KERN_ALERT "Progger: mac=0x%016llx\n", dHostId);
	}
	ret = 0;
	write_to_tty("Progger: module insertion successful\n");
	return ret;

err_sys_enter:
	printk(KERN_ALERT "Progger: err_sys_enter, unregister _exit\n");
#if 0																		/* 31 May TJChoi : add this for error situation */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
	compat_unregister_trace(syscall_exit_probe,
						"sys_exit", tp_sys_exit);
#else
	unregister_trace_syscall_exit(syscall_exit_probe);
#endif
#else
	cleanup_module();
#endif

	return 0;
}

TRACEPOINT_PROBE(syscall_enter_probe, struct pt_regs *regs, long syscall_id) 
{
	struct timespec start_ts;
	struct process_info proc_info;
	unsigned int old_fd;

//	printk(KERN_ALERT "Progger: syscall_enter_probe \n");
#if 1
	#ifdef LIMITED_TESTING_ONLY 			/* TJ makes this activating */
	if (count_enter[syscall_id] > 10)
		return;
	count_enter[syscall_id]++;	
	#endif
	
        getnstimeofday(&start_ts);

	proc_info.uid = current_uid();
	proc_info.pid = current->pid;
	proc_info.proc_name = current->comm;
//	printk(KERN_ALERT "Progger: syscall_%s \n", proc_info.proc_name);
	
//	printk(KERN_ALERT "Progger: syscall_enter_probe proc_info %d \n", syscall_id);

	switch (syscall_id) {
	case __NR_open:
		/* if an error happened while creating the Q to store pt_regs
		 * of open syscalls, handle open syscalls without using the 
		 * return value */
		if (!record_open_regs)
			sys_open_handler(regs, record_open_regs, 
					NO_OPEN_RETVAL, start_ts, sock, 
								proc_info);
		else
		/* add pt_regs for the Open syscall to Queue for the purposes
		 * of finding the corresponding sys_exit return values */
			if (q_opened != NULL) {
				mutex_lock(&progger_mutex);
					enqueue(q_opened, regs, proc_info,
								 start_ts);
				mutex_unlock(&progger_mutex);
			}
		break;

	case __NR_read:
	case __NR_pread64:
		sys_read_write_handler(regs, PSCT_FILE_READ, syscall_id, 
						start_ts, sock, proc_info);
		break;

	case __NR_write:
	case __NR_pwrite64:
		sys_read_write_handler(regs, PSCT_FILE_WRITE, 
					syscall_id, start_ts, sock, proc_info);
		break;

	case __NR_close:
		sys_close_handler(regs, start_ts, sock, proc_info);
		break;

	case __NR_mkdir:
		sys_mkdir_rmdir_handler(regs, PSCT_DIRNODE_CREATE, start_ts, 
							sock, proc_info);
		break;

	case __NR_rmdir:
		sys_mkdir_rmdir_handler(regs, PSCT_DIRNODE_DELETE, start_ts,
							sock, proc_info);
		break;

	case __NR_rename:
		sys_rename_link_handler(regs, PSCT_DIRNODE_RENAME, start_ts, 
							sock, proc_info);
		break;

	case __NR_dup:
	case __NR_dup2:
		sys_dup_handler(regs, syscall_id, start_ts, sock, proc_info);
		break;
	
	case __NR_sendfile:
		sys_sendfile_handler(regs, start_ts, sock, proc_info);
		break;   

	case __NR_link:
		sys_rename_link_handler(regs, PSCT_DIRNODE_RENAME, start_ts, 
							sock, proc_info);
		break;

	case __NR_unlink:
		sys_unlink_handler(regs, __NR_unlink, start_ts, sock, 
								proc_info);
		break;
	
	case __NR_unlinkat:
		sys_unlink_handler(regs, __NR_unlinkat, start_ts, sock, 
								proc_info);
		break;

	case __NR_symlink:
		sys_rename_link_handler(regs, PSCT_DIRNODE_LINK, start_ts, 
							sock, proc_info);
		break; 

	case __NR_chmod:
		sys_chmod_handler(regs, start_ts, sock, proc_info);
		break;

	case __NR_fchmod:
		sys_fchmod_handler(regs, start_ts, sock, proc_info);
		break;

	case __NR_chown:
		sys_chown_handler(regs, __NR_chown, start_ts, sock, proc_info);
		break;

	case __NR_fchown:
                sys_fchown_handler(regs, start_ts, sock, proc_info);
                break;

	case __NR_lchown:
                sys_chown_handler(regs, __NR_lchown, start_ts, sock, proc_info);
                break;

	case __NR_pipe:
	case __NR_pipe2:
		sys_pipe_handler(regs, start_ts, sock, proc_info);
		break; 

//	TODO: handle syscalls with filenames relative to dirfd
//	case __NR_fchownat:
  //              sys_fchownat_handler(regs, start_ts, sock, proc_info);
    //            break;
/*	case __NR_linkat:
		sys_linkat_handler(regs, start_ts, sock, proc_info);
		break;
	case __NR_fchmodat:
		sys_fchmodat_handler(regs, start_ts, sock, proc_info);
		break;*/


	/* Socket syscalls untested *
	case __NR_socket:
		sys_socket_handler(regs);
                break;
	case __NR_connect:
		sys_connect_handler(regs);
		break;
	case __NR_send:
                sys_sendto_handler(regs, __NR_send);
                break;
	case __NR_sendto:
		sys_sendto_handler(regs, __NR_sendto);
		break;
	case __NR_sendmsg:
		sys_sendmsg_handler(regs);
		break;
	case __NR_accept:
		sys_accept_handler(regs);
		break;
	case __NR_recvfrom:
		sys_recvfrom_handler(regs);
		break;
	case __NR_recvmsg:
		sys_recvmsg_handler(regs);
		break;		*/
	default:
		break;
	}
#endif
}

TRACEPOINT_PROBE(syscall_exit_probe, struct pt_regs *regs, long ret) 
{
	struct node_regs *matched_node;

	/* if q_opened has been successfully created */
	if (record_open_regs) {										/* 30 May TJChoi : org (record_open_regs && q_opened) because of duplication of conditions */
		mutex_lock(&progger_mutex);
			
			/* find matching pt_regs in queue and delete if found */
			matched_node = found_node(q_opened, regs);
			if (matched_node != NULL)

				/* handle sys_open with the return value */
				sys_open_handler(regs, record_open_regs, ret, 
						matched_node->ts, sock,
						matched_node->proc_info);
			
		mutex_unlock(&progger_mutex);
	}
}

void cleanup_module(void)
{
	#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
        	compat_unregister_trace(syscall_exit_probe,
                                                "sys_exit", tp_sys_exit);
		compat_unregister_trace(syscall_enter_probe,
                                                "sys_enter", tp_sys_enter);
	#else
		unregister_trace_syscall_exit(syscall_exit_probe);
		unregister_trace_syscall_exit(syscall_enter_probe);
        #endif

	if (q_opened) kfree(q_opened);

	if(sock != NULL)											/* 31 May TJChoi : added checking sock */
	{
		WARN_ON(!sock);
		kfree(sock);
	}
	
	/* Progger cannot be removed for security purposes, but removing it for testing purposes */
	printk(KERN_ALERT "Progger: module removed!\n");
}

#ifdef TJ															/* MODULE_PARAM 11 Jun TJChoi add module load/unload */
module_init(init_module);
module_exit(cleanup_module);
#endif

