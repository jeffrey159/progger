#include <linux/netpoll.h>
#include <linux/crc32.h>
#include <net/inet_common.h>

#include "./progger-format/logFormat.h"
#include "definitions.h"	/* TJ to seperate codes according to defines.  April, 2018 */
#include "log.h"			/* TJ for log messages  April, 2018 */

#ifdef ABSENCE_STRLEN_USER
#include "./progger_utils.h"
#endif

#define MESSAGE_SIZE 1024

#ifdef TEST
progger_uint32 process_list[PID_MAX_DEFAULT] = { 0 };
#else
progger_uint32 process_list[0xFFFF + 1] = { 0 };
#endif
const char* type_names[] = {"PSCT_USER_INFO", "PSCT_PROCESS_CREATE", "PSCT_PROCESS_EXIT", "PSCT_FILE_OPEN", "PSCT_FILE_CLOSE", "PSCT_FILE_READ", "PSCT_FILE_WRITE", "PSCT_SOCKET_OPEN", "PSCT_SOCKET_CLOSE", "PSCT_SOCKET_READ", "PSCT_SOCKET_WRITE", "PSCT_DIRNODE_CREATE", "PSCT_DIRNODE_DELETE", "PSCT_DIRNODE_RENAME", "PSCT_DIRNODE_LINK", "PSCT_DIRNODE_CHANGE_OWNER", "PSCT_DIRNODE_CHANGE_PERMISSIONS", "PSCT_HANDLE_DUPLICATE"};

#ifdef SOCKET_HEADER_ERROR						/* 2 June TJChoi : for handling error */
static struct progger_header error_header;
#endif

static DEFINE_MUTEX(sock_mutex);

struct progger_header *new_header(enum progger_syscallTypes type,
                                                size_t expansion_size,
                                                void **expansion_location,
                                                struct process_info proc_info,
                                                struct timespec ts, 
						bool check_process,
						struct socket *sock);

void add_attribute(struct progger_header *header,
                                                struct progger_attribute *attr,
                                                 progger_uint16 attribute_len);
void finish_header(struct progger_header *header, struct timespec start_ts);
int write_log(char *buf, int buf_len, struct socket *sock,
                                        enum progger_syscallTypes type);

/*
int log_user(kuid_t user_id)
{
	int status = 0;
	struct timespec start_ts;
	char username[1024];
	char user_sid[256];
	int id = (int)user_id;

	// log user details if they have never been encountered before
	if (user_list[id] != user_id) {
		user_list[id] = user_id;

        	getnstimeofday(&start_ts);
		memset(username, 0, sizeof(char) * 1024);

		if (!get_username(&username)) {
			user_list[id] = 0;
			return -1;
		}
	}	
}*/

int log_process(struct process_info proc_info, struct timespec ts, 
							struct socket *sock)
{
	int status = 0;
	struct timespec start_ts;	
	int expansion_size;
	char *filename_location;
	struct progger_processAttribute *proc_attrib;
	struct progger_header *header;
	
	if (process_list[((int)proc_info.pid)] == proc_info.pid) 
		return status;

	// process not found in list, so add it and log the process name
	process_list[((int)proc_info.pid)] = proc_info.pid;

	getnstimeofday(&start_ts);
	expansion_size = sizeof(struct progger_processAttribute) 
						+ strlen(proc_info.proc_name);

	header = new_header(PSCT_PROCESS_CREATE, expansion_size, 
						(void **)&proc_attrib,
						proc_info, ts, false, sock);
#ifdef SOCKET_HEADER_ERROR						/* 5 June TJChoi : for handling error */
	if(proc_attrib != NULL)
	{
		proc_attrib->processHandle = proc_info.pid;
		proc_attrib->processPathLength = strlen(proc_info.proc_name);

		filename_location = (char *)(&proc_attrib[1]);
		memcpy(filename_location, proc_info.proc_name,
							strlen(proc_info.proc_name));

		add_attribute(header, &proc_attrib->header, expansion_size);
	}
#else
	proc_attrib->processHandle = proc_info.pid;
	proc_attrib->processPathLength = strlen(proc_info.proc_name);

	filename_location = (char *)(&proc_attrib[1]);
	memcpy(filename_location, proc_info.proc_name, 
						strlen(proc_info.proc_name));

	add_attribute(header, &proc_attrib->header, expansion_size);
#endif
	finish_header(header, start_ts);

	status = write_log((char *)header, header->length, sock, 
							PSCT_PROCESS_CREATE);

	WARN_ON(!header);
#ifdef SOCKET_HEADER_ERROR						/* 2 June TJChoi : for handling error */
	if(header!=&error_header)
		kfree(header);
#else
	kfree(header);
#endif

	return status;
}

struct progger_header *new_header(enum progger_syscallTypes type, 
						size_t expansion_size,
						void **expansion_location,
						struct process_info proc_info,
						struct timespec ts,
						bool check_process,
						struct socket *sock)
{
	int status = 0;
#ifdef SOCKET_HEADER_ERROR						/* 2 June TJChoi : for handling error */
	struct progger_header* ret = NULL;

	ret = kmalloc(sizeof(struct progger_header) +
							expansion_size, GFP_KERNEL);
	if(ret == NULL)
	{
		ret = &error_header;
		memset(ret, 0, sizeof(struct progger_header));
	}
	else
	{
		memset(ret, 0, sizeof(struct progger_header) + expansion_size);
	}
#else
	/* Allocate continuous block of memory for header and attribute */
	struct progger_header *ret = kmalloc(sizeof(struct progger_header) + 
						expansion_size, GFP_KERNEL);


	if (!ret)
		printk(KERN_ALERT 
			"Progger: new_header/ERROR kmalloc progger_hdr \n");
	memset(ret, 0, sizeof(struct progger_header) + expansion_size);
#endif
	
	WARN_ON(!ret);
	ret->version = 0;
	ret->length = sizeof(struct progger_header);

	ret->platform = (progger_uint8)PP_LINUX;
	ret->type = (progger_uint8)type;

	ret->hostId = dHostId;																/* 14 June TJChoi : for HostId  org HOST_ID */
	ret->timestamp = to_nanoseconds(ts);

	ret->userId = proc_info.uid;
	ret->processId = proc_info.pid;

#if 1																					/* 2 June TJChoi : This causes infinite loop */
	//	status = log_user(ret->userId);
	status = log_process(proc_info, ts, sock);
#endif

	ret->attributeCount = 0;

#ifdef SOCKET_HEADER_ERROR						/* 2 June TJChoi : for handling error */
	if((ret!=&error_header)&&(expansion_size>0))
		*expansion_location =
				(((char *)(ret))
					+ sizeof(struct progger_header));
	else
		*expansion_location = NULL;
#else
	if (expansion_size > 0)
		*expansion_location = 
				(((char *)(ret)) 
					+ sizeof(struct progger_header));
#endif

	return ret;
}

void add_attribute(struct progger_header *header, 
						struct progger_attribute *attr,
						 progger_uint16 attribute_len)
{
	if (attr == NULL) {
		printk(KERN_ALERT "Progger: add_attribute/attr NULL\n");
		return;
	}
	if (header == NULL) {
		printk(KERN_ALERT "Progger: add_attribute/hdr NULL\n");
		return;
	}

	attr->length = attribute_len;
	header->attributeCount++;
	header->length = header->length + attribute_len;
}

void finish_header(struct progger_header *header, struct timespec start_ts)
{
	struct timespec current_ts;

	header->version = 100;
	getnstimeofday(&current_ts);
	header->timeDelta = timespec_diff(start_ts, current_ts);
}

int write_log(char *buf, int buf_len, struct socket *sock, 
					enum progger_syscallTypes type)
{
	int ret = 1;
	struct msghdr msg;	
	char *redis_push_msg;
	int redis_push_len;
	mm_segment_t oldfs;
        struct iovec iov;
    int index=0;			/* TJ */

	WARN_ON(!sock);

	redis_push_msg = (char *)kmalloc(buf_len + 64, GFP_KERNEL);
	if (!redis_push_msg) {
		printk(KERN_ALERT "Progger: write_log/ redis_push_msg NULL\n");
		return -1;
	}

	memset(redis_push_msg, 0, buf_len + 64);
	redis_push_len = snprintf(redis_push_msg, buf_len + 64, 
		"*3\r\n$5\r\nRPUSH\r\n$11\r\ntestingList\r\n$%d\r\n", buf_len);


	WARN_ON(!(redis_push_len + 12 < 64));

#if 1
	memcpy(redis_push_msg + redis_push_len, buf, buf_len);
#else
	memcpy(redis_push_msg + redis_push_len, buf, buf_len);
	//memcpy(&redis_push_msg[redis_push_len], buf, buf_len);
	index = redis_push_len;
#endif

	redis_push_msg[redis_push_len + buf_len] = 13;	// CR (\r)
	redis_push_msg[redis_push_len + buf_len + 1] = 10;	// LF (\n)
	redis_push_len += buf_len + 2;
	
	iov.iov_base = redis_push_msg;
	iov.iov_len = redis_push_len;

	iov_iter_init(&msg.msg_iter, 0, &iov, 0, redis_push_len);
	
	msg.msg_name = 0;	// ptr to socket address structure
        msg.msg_namelen = 0;	// size of socket address structure

	msg.msg_control = NULL;	// ancillary data
        msg.msg_controllen = 0;	// ancillary data buffer length
        msg.msg_flags = 0;	// flags on received message
	msg.msg_iocb = NULL;	// ptr to iocb for async requests

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	mutex_lock(&sock_mutex);
	ret = sock_sendmsg(sock, &msg);
	mutex_unlock(&sock_mutex);

	//printk(KERN_ALERT "Progger buf: %s", &iov.iov_base[index+sizeof(struct progger_filenameAttribute)+sizeof(struct progger_header)]);

	if (!ret) {
		sock = NULL;
		write_to_tty("\nProgger: ERROR sending message to Redis\n");
	}
//	printk(KERN_ALERT "Progger: write_log/ redis_push_msg NULL\n");
	
	set_fs(oldfs);

	kfree(redis_push_msg);	

	return ret;
}

int log_fs_close(unsigned int fd, unsigned int inode_num, struct timespec ts, 
			struct process_info proc_info, struct socket *sock)
{
	int status = 1;

	struct progger_fileAttribute *file_attrib;
	struct progger_header *header;

	header = new_header(PSCT_FILE_CLOSE, 
				sizeof(struct progger_fileAttribute),
				(void **)&file_attrib, proc_info, ts, true, sock);
#ifdef SOCKET_HEADER_ERROR						/* 3 June TJChoi : for handling error */
	if(file_attrib != NULL)
	{
		file_attrib->fileID = inode_num;
		file_attrib->fileHandleID = fd;

		add_attribute(header, &file_attrib->header,
						sizeof(struct progger_fileAttribute));
	}
	finish_header(header, ts);
	status = write_log((char *)header, header->length, sock,
							PSCT_FILE_CLOSE);

	WARN_ON(!header);
	if(header != &error_header)
		kfree(header);
#else
	if (header == NULL)
		printk(KERN_ALERT "Progger: ERROR header NULL\n");
	if (file_attrib ==NULL)
		printk(KERN_ALERT "Progger: ERROR file_attrib NULL\n");
	
	file_attrib->fileID = inode_num;
	file_attrib->fileHandleID = fd;

	add_attribute(header, &file_attrib->header, 
					sizeof(struct progger_fileAttribute));
	finish_header(header, ts);

	status = write_log((char *)header, header->length, sock, 
							PSCT_FILE_CLOSE);

	WARN_ON(!header);
	kfree(header);	
#endif
	return status;
}

int log_fs_read_write(enum progger_syscallTypes type, unsigned int fd, 
				unsigned int inode_num, 
				size_t count, progger_int64 pos, 
				struct timespec ts, 
			struct process_info proc_info, struct socket *sock)
{
	int status = 1;
	struct progger_fileReadWriteAttribute *rw_attrib;
	struct progger_header *header;

	header = new_header(type,sizeof(struct progger_fileReadWriteAttribute), 
				(void **)&rw_attrib, proc_info, ts, true, sock);
#ifdef SOCKET_HEADER_ERROR						/* 3 June TJChoi : for handling error */
	if (rw_attrib != NULL) {
		rw_attrib->fileID = inode_num;
		rw_attrib->fileHandleID = fd;
		rw_attrib->position = pos;
		rw_attrib->length = count;

		add_attribute(header, &rw_attrib->header,
				sizeof(struct progger_fileReadWriteAttribute));
	}
	finish_header(header, ts);
	status = write_log((char *)header, header->length, sock, type);

	WARN_ON(!header);
	if(header != &error_header)
		kfree(header);
#else
	if (header == NULL) {
		printk(KERN_ALERT "Progger: ERROR header NULL\n");
		return -1;
	}

	if (rw_attrib == NULL) {
		printk(KERN_ALERT "Progger: ERROR rw_attrib NULL\n");
		return -1;
	}
	
	rw_attrib->fileID = inode_num;
	rw_attrib->fileHandleID = fd;
	rw_attrib->position = pos;
	rw_attrib->length = count;

	add_attribute(header, &rw_attrib->header, 
			sizeof(struct progger_fileReadWriteAttribute));
	finish_header(header, ts);

	status = write_log((char *)header, header->length, sock, type);

	WARN_ON(!header);
	kfree(header);	
#endif
	return status;
}

#ifdef ABSENCE_STRLEN_USER
int log_fs_open(STR_IN_USERAREA *stFilename, long fd, unsigned long inode_num, bool created,
			struct timespec ts,
			struct process_info proc_info, struct socket *sock)
#else
int log_fs_open(char *fname, long fd, unsigned long inode_num, bool created, 
			struct timespec ts, 
			struct process_info proc_info, struct socket *sock)
#endif
{
	int status;
	char *fname_location;

#ifdef ABSENCE_STRLEN_USER
	size_t expansion_size = sizeof(struct progger_fileOpenAttribute)+ stFilename->user_str_len;		/* TJ: added 0x1 for null terminated string */
#else
	size_t expansion_size = sizeof(struct progger_fileOpenAttribute)
					+ strlen(fname);
#endif
	struct progger_fileOpenAttribute *open_attrib;
	struct progger_header *header;

	header = new_header(PSCT_FILE_OPEN, expansion_size, 
				(void **)&open_attrib, proc_info, ts, true, sock);

#ifdef SOCKET_HEADER_ERROR						/* 3 June TJChoi : for handling error */
    if (open_attrib != NULL) {
    	open_attrib->fileID = inode_num;
    	open_attrib->fileHandleID = fd;
    	open_attrib->created = created;
#ifdef ABSENCE_STRLEN_USER
    	open_attrib->filenameLength = stFilename->user_str_len;
#else
    	open_attrib->filenameLength = strlen(fname);
#endif

    	fname_location = (char *)(&open_attrib[1]);
#ifdef ABSENCE_STRLEN_USER
    	memcpy(fname_location, stFilename->user_str, stFilename->user_str_len);
#else
    	memcpy(fname_location, fname, strlen(fname));
#endif
    	LOG_STR_BUF((char *)(&open_attrib[1]), open_attrib->filenameLength);
    	add_attribute(header, &open_attrib->header, expansion_size);
	}

	finish_header(header, ts);
	status = write_log((char *)header, header->length, sock,
							PSCT_FILE_OPEN);

	WARN_ON(!header);
	if(header != &error_header)
		kfree(header);
#else
	if (header == NULL) { 
		printk(KERN_ALERT "Progger: ERROR header NULL\n");
		return -1;
	}
    if (open_attrib == NULL) {
		printk(KERN_ALERT "Progger: ERROR open_attrib NULL\n");
		return -1;
	}

	open_attrib->fileID = inode_num;
	open_attrib->fileHandleID = fd;
	open_attrib->created = created;
#ifdef ABSENCE_STRLEN_USER
	open_attrib->filenameLength = stFilename->user_str_len;
#else
	open_attrib->filenameLength = strlen(fname);
#endif

	fname_location = (char *)(&open_attrib[1]);
#ifdef ABSENCE_STRLEN_USER
	memcpy(fname_location, stFilename->user_str, stFilename->user_str_len);
#else
	memcpy(fname_location, fname, strlen(fname));
#endif

	LOG_STR_BUF((char *)(&open_attrib[1]), open_attrib->filenameLength);

	add_attribute(header, &open_attrib->header, expansion_size);

	finish_header(header, ts);
	
	status = write_log((char *)header, header->length, sock, 
							PSCT_FILE_OPEN);

	WARN_ON(!header);
        kfree(header);
#endif
	return status;
}

#ifdef ABSENCE_STRLEN_USER
int log_fs_link(STR_IN_USERAREA *stOldFilename, STR_IN_USERAREA *stNewFilename, struct timespec ts,
			struct process_info proc_info, struct socket *sock)
#else
int log_fs_link(char *old_fname, char *new_fname, struct timespec ts, 
			struct process_info proc_info, struct socket *sock)
#endif
{
	int status = 1;
        char *old_fname_location;
	char *new_fname_location;

#ifdef ABSENCE_STRLEN_USER
    size_t expansion_size = sizeof(struct progger_fileLinkAttribute)
						+ stOldFilename->user_str_len + stNewFilename->user_str_len;		/* TJ: added 0x1 for null terminated string */
#else
        size_t expansion_size = sizeof(struct progger_fileLinkAttribute) 
							+ strlen(old_fname)
							+ strlen(new_fname);
#endif
	struct progger_fileLinkAttribute *link_attrib;
	struct progger_header *header;
	
	header = new_header(PSCT_DIRNODE_LINK, 
						expansion_size, 
						(void **)&link_attrib, 
						proc_info, ts, true, sock);
#ifdef SOCKET_HEADER_ERROR						/* 5 June TJChoi : for handling error */
	if (link_attrib != NULL) {
#ifdef ABSENCE_STRLEN_USER
		link_attrib->oldFilenameLength = stOldFilename->user_str_len;
		link_attrib->newFilenameLength = stNewFilename->user_str_len;

		old_fname_location = (char *)(&link_attrib[1]);
		memcpy(old_fname_location, stOldFilename->user_str, stOldFilename->user_str_len);
#if 0
		new_fname_location = (char *)(&link_attrib[stOldFilename->user_str_len]);
#else
		new_fname_location = (char *)(&old_fname_location[stOldFilename->user_str_len]);
#endif
		memcpy(new_fname_location, stNewFilename->user_str, stNewFilename->user_str_len);
#else
		link_attrib->oldFilenameLength = strlen(old_fname);
		link_attrib->newFilenameLength = strlen(new_fname);

		old_fname_location = (char *)(&link_attrib[1]);
		memcpy(old_fname_location, old_fname, strlen(old_fname));

		new_fname_location = (char *)(&link_attrib[strlen(old_fname)]);
		memcpy(new_fname_location, new_fname, strlen(new_fname));
#endif
		LOG_STR_BUF((char *)(&link_attrib[1]), link_attrib->oldFilenameLength);
		add_attribute(header, &link_attrib->header, expansion_size);
	}
#else
	if (header == NULL) {
                printk(KERN_ALERT "Progger: ERROR header NULL\n");
		return -1;
	}
        if (link_attrib == NULL) {
                printk(KERN_ALERT "Progger: ERROR link_attrib NULL\n");
		return -1;
	}

#ifdef ABSENCE_STRLEN_USER
	link_attrib->oldFilenameLength = stOldFilename->user_str_len;
	link_attrib->newFilenameLength = stNewFilename->user_str_len;

	old_fname_location = (char *)(&link_attrib[1]);
	memcpy(old_fname_location, stOldFilename->user_str, stOldFilename->user_str_len);
#if 0
	new_fname_location = (char *)(&link_attrib[stOldFilename->user_str_len]);
#else
	new_fname_location = (char *)(&old_fname_location[stOldFilename->user_str_len]);
#endif
	memcpy(new_fname_location, stNewFilename->user_str, stNewFilename->user_str_len);
#else
	link_attrib->oldFilenameLength = strlen(old_fname);
	link_attrib->newFilenameLength = strlen(new_fname);

	old_fname_location = (char *)(&link_attrib[1]);
	memcpy(old_fname_location, old_fname, strlen(old_fname));
		
	new_fname_location = (char *)(&link_attrib[strlen(old_fname)]);
	memcpy(new_fname_location, new_fname, strlen(new_fname));
#endif

	LOG_STR_BUF((char *)(&link_attrib[1]), link_attrib->oldFilenameLength);

	add_attribute(header, &link_attrib->header, expansion_size);
#endif
        finish_header(header, ts);
        status = write_log((char *)header, header->length, sock, PSCT_DIRNODE_LINK);
        WARN_ON(!header);
#ifdef SOCKET_HEADER_ERROR						/* 5 June TJChoi : for handling error */
	if(header != &error_header)
		kfree(header);
#else
        kfree(header);
#endif
        return status;
}

#ifdef ABSENCE_STRLEN_USER
int log_fs_change_permissions(STR_IN_USERAREA *stFilename, int fd, long inode,
							struct timespec ts, struct process_info proc_info,
							struct socket *sock)
#else
int log_fs_change_permissions(char *filename, int fd, long inode, 
			struct timespec ts, struct process_info proc_info, 
							struct socket *sock)
#endif
{
	int status = 1;
	char *filename_location;

#ifdef ABSENCE_STRLEN_USER
	size_t expansion_size = sizeof(struct progger_changePermissionsAttribute)+ stFilename->user_str_len;		/* TJ: added 0x1 for null terminated string */
#else
	size_t expansion_size = 
		sizeof(struct progger_changePermissionsAttribute) 
							+ strlen(filename);
#endif
	struct progger_changePermissionsAttribute *perm_attrib;
	struct progger_header *header;

	header = new_header(PSCT_DIRNODE_CHANGE_PERMISSIONS, expansion_size,
				(void **)&perm_attrib, proc_info, ts, true, sock);
#ifdef SOCKET_HEADER_ERROR						/* 5 June TJChoi : for handling error */
	if(perm_attrib != NULL)
	{
#ifdef ABSENCE_STRLEN_USER
		perm_attrib->filenameLength = stFilename->user_str_len;
#else
		perm_attrib->filenameLength = strlen(filename);
#endif
		perm_attrib->fileID = inode;
		perm_attrib->fileHandleID = fd;
		filename_location = (char *)(&perm_attrib[1]);
#ifdef ABSENCE_STRLEN_USER
		memcpy(filename_location, stFilename->user_str, stFilename->user_str_len);
#else
		memcpy(filename_location, filename, strlen(filename));
#endif
		LOG_STR_BUF((char *)(&perm_attrib[1]), perm_attrib->filenameLength);
		add_attribute(header, &perm_attrib->header, expansion_size);
	}
#else
#ifdef ABSENCE_STRLEN_USER
	perm_attrib->filenameLength = stFilename->user_str_len;
#else
	perm_attrib->filenameLength = strlen(filename);
#endif
	perm_attrib->fileID = inode;
	perm_attrib->fileHandleID = fd;

	filename_location = (char *)(&perm_attrib[1]);
#ifdef ABSENCE_STRLEN_USER
	memcpy(filename_location, stFilename->user_str, stFilename->user_str_len);
#else
	memcpy(filename_location, filename, strlen(filename));
#endif
	LOG_STR_BUF((char *)(&perm_attrib[1]), perm_attrib->filenameLength);

	add_attribute(header, &perm_attrib->header, expansion_size);
#endif
	finish_header(header, ts);
	status = write_log((char *)header, header->length, sock, PSCT_DIRNODE_CHANGE_PERMISSIONS);

	WARN_ON(!header);
#ifdef SOCKET_HEADER_ERROR						/* 5 June TJChoi : for handling error */
	if(header != &error_header)
		kfree(header);
#else
	kfree(header);
#endif
	return status;
}

#ifdef ABSENCE_STRLEN_USER
int log_fs_change_owner(STR_IN_USERAREA *stFilename, int fd, long inode, uid_t owner,
			struct timespec ts, struct process_info proc_info,
							 struct socket *sock)
#else
int log_fs_change_owner(char *filename, int fd, long inode, uid_t owner, 
			struct timespec ts, struct process_info proc_info,
							 struct socket *sock)
#endif
{
	int status = 1;
	char *filename_location;
#ifdef ABSENCE_STRLEN_USER
	int expansion_size = sizeof(struct progger_setOwnerAttribute)
								+ stFilename->user_str_len;		/* TJ: added 0x1 for null terminated string */
#else
	int expansion_size = sizeof(struct progger_setOwnerAttribute) 
							+ strlen(filename);
#endif
	struct progger_setOwnerAttribute *set_owner_attrib;
	struct progger_header *header;

	header = new_header(PSCT_DIRNODE_CHANGE_OWNER, 
			expansion_size, (void **)&set_owner_attrib, 
					proc_info, ts, true, sock);	
#ifdef SOCKET_HEADER_ERROR						/* 5 June TJChoi : for handling error */
	if(set_owner_attrib != NULL)
	{
#ifdef LOG_SYSCALL
		printk(KERN_ALERT "Progger: log_fs_change_owner|header success\n");
#endif
		set_owner_attrib->fileID = inode;
		set_owner_attrib->fileHandleID = fd;
#ifdef ABSENCE_STRLEN_USER
		set_owner_attrib->filenameLength = stFilename->user_str_len;
#else
		set_owner_attrib->filenameLength = strlen(filename);
#endif
		set_owner_attrib->newOwnerID = owner;
		set_owner_attrib->sidLength = 0;

		filename_location = (char *)(&set_owner_attrib[1]);
#ifdef ABSENCE_STRLEN_USER
		memcpy(filename_location, stFilename->user_str, stFilename->user_str_len);
#else
		memcpy(filename_location, filename, strlen(filename));
#endif
		add_attribute(header, &set_owner_attrib->header, expansion_size);
		LOG_STR_BUF((char *)(&set_owner_attrib[1]), set_owner_attrib->filenameLength);
	}
#else
	if (header == NULL) { 
		printk(KERN_ALERT "Progger: ERROR header NULL\n");
		return -1;
	}
        if (set_owner_attrib == NULL) {
		printk(KERN_ALERT "Progger: ERROR open_attrib NULL\n");
		return -1;
	}

#ifdef LOG_SYSCALL
	printk(KERN_ALERT "Progger: log_fs_change_owner|header success\n");
#endif
	
	set_owner_attrib->fileID = inode;
	set_owner_attrib->fileHandleID = fd;
#ifdef ABSENCE_STRLEN_USER
	set_owner_attrib->filenameLength = stFilename->user_str_len;
#else
	set_owner_attrib->filenameLength = strlen(filename);
#endif
	set_owner_attrib->newOwnerID = owner;
	set_owner_attrib->sidLength = 0;

	filename_location = (char *)(&set_owner_attrib[1]);
#ifdef ABSENCE_STRLEN_USER
	memcpy(filename_location, stFilename->user_str, stFilename->user_str_len);
#else
	memcpy(filename_location, filename, strlen(filename));
#endif

	//printk(KERN_ALERT "Progger: log_fs_change_owner|memcpy success\n");

	add_attribute(header, &set_owner_attrib->header, expansion_size);
	LOG_STR_BUF((char *)(&set_owner_attrib[1]), set_owner_attrib->filenameLength);
#endif
	finish_header(header, ts);
	status = write_log((char *)header, header->length, sock, 
						PSCT_DIRNODE_CHANGE_OWNER);

    WARN_ON(!header);
#ifdef SOCKET_HEADER_ERROR						/* 5 June TJChoi : for handling error */
	if(header != &error_header)
		kfree(header);
#else
    kfree(header);
#endif
	return status;
}

int log_handle_duplicate(unsigned int old_fd, unsigned int old_inode, 
				unsigned int new_fd, unsigned int new_inode, 
				int type, struct timespec ts, 
				struct process_info proc_info, 
							struct socket *sock)
{
	int status = 1;
	struct progger_handleDuplicateAttribute *dup_attrib;
	struct progger_header *header;

	header = new_header(PSCT_HANDLE_DUPLICATE, 
				sizeof(struct progger_handleDuplicateAttribute),
					 	(void**)&dup_attrib, 
						proc_info, ts, true, sock);
#ifdef SOCKET_HEADER_ERROR						/* 5 June TJChoi : for handling error */
	if(dup_attrib != NULL)
	{
		dup_attrib->oldfileID = old_inode;
		dup_attrib->oldfileHandleID = old_fd;
		dup_attrib->newfileID = new_inode;
		dup_attrib->newfileHandleID = new_fd;
		dup_attrib->type = type;

		add_attribute(header, &dup_attrib->header, sizeof(struct progger_handleDuplicateAttribute));
	}
#else
	dup_attrib->oldfileID = old_inode;
	dup_attrib->oldfileHandleID = old_fd;
	dup_attrib->newfileID = new_inode;
	dup_attrib->newfileHandleID = new_fd;
	dup_attrib->type = type;	

	add_attribute(header, &dup_attrib->header, 
			sizeof(struct progger_handleDuplicateAttribute));
#endif
	finish_header(header, ts);
    status = write_log((char *)header, header->length, sock, PSCT_HANDLE_DUPLICATE);

	WARN_ON(!header);
#ifdef SOCKET_HEADER_ERROR						/* 5 June TJChoi : for handling error */
	if(header != &error_header)
	    kfree(header);
#else
	kfree(header);
#endif
        return status;
}

#ifdef ABSENCE_STRLEN_USER
int log_fs_rename_hardlink(enum progger_syscallTypes type,
		STR_IN_USERAREA *stSrcFilename, STR_IN_USERAREA *stDestFilename, struct timespec ts,
	struct process_info proc_info, struct socket *sock)
#else
int log_fs_rename_hardlink(enum progger_syscallTypes type, 
	char *src_fname, char *target_fname, struct timespec ts, 
			struct process_info proc_info, struct socket *sock)
#endif
{
	int status = 1;
	char *src_fname_location;
	char *target_fname_location;
#ifdef ABSENCE_STRLEN_USER
	size_t expansion_size = sizeof(struct progger_fileLinkAttribute) 
								+ stSrcFilename->user_str_len + stDestFilename->user_str_len;		/* TJ: added 0x1 for null terminated string */
#else
	size_t expansion_size = sizeof(struct progger_fileLinkAttribute)
							+ strlen(src_fname) 
							+ strlen(target_fname);
#endif
	struct progger_fileLinkAttribute *file_link_attrib;
	struct progger_header *header;

	header = new_header(type, expansion_size, 
					(void **)&file_link_attrib, proc_info, 
								ts, true, sock);
#ifdef SOCKET_HEADER_ERROR						/* 5 June TJChoi : for handling error */
	if(file_link_attrib != NULL)
	{
#ifdef ABSENCE_STRLEN_USER
		file_link_attrib->oldFilenameLength = stSrcFilename->user_str_len;
		file_link_attrib->newFilenameLength = stDestFilename->user_str_len;
#else
		file_link_attrib->oldFilenameLength = strlen(src_fname);
		file_link_attrib->newFilenameLength = strlen(target_fname);
#endif

		src_fname_location = (char *)(&file_link_attrib[1]);
#ifdef ABSENCE_STRLEN_USER
		memcpy(src_fname_location, stSrcFilename->user_str, stSrcFilename->user_str_len);
		target_fname_location =
			(char *)(&src_fname_location[stSrcFilename->user_str_len]);
		memcpy(target_fname_location, stDestFilename->user_str, stDestFilename->user_str_len);
#else
		memcpy(src_fname_location, src_fname, strlen(src_fname));
		target_fname_location =
			(char *)(&src_fname_location[strlen(src_fname)]);
		memcpy(target_fname_location, target_fname, strlen(target_fname));
#endif
		add_attribute(header, &file_link_attrib->header, expansion_size);
		LOG_STR_BUF((char *)(&file_link_attrib[1]), file_link_attrib->oldFilenameLength);
	}
#else
#ifdef ABSENCE_STRLEN_USER
	file_link_attrib->oldFilenameLength = stSrcFilename->user_str_len;
	file_link_attrib->newFilenameLength = stDestFilename->user_str_len;
#else
	file_link_attrib->oldFilenameLength = strlen(src_fname);
	file_link_attrib->newFilenameLength = strlen(target_fname);
#endif
	
	src_fname_location = (char *)(&file_link_attrib[1]);
#ifdef ABSENCE_STRLEN_USER
	memcpy(src_fname_location, stSrcFilename->user_str, stSrcFilename->user_str_len);
	target_fname_location =
			(char *)(&src_fname_location[stSrcFilename->user_str_len]);
	memcpy(target_fname_location, stDestFilename->user_str, stDestFilename->user_str_len);
#else
	memcpy(src_fname_location, src_fname, strlen(src_fname));
	target_fname_location = 
			(char *)(&src_fname_location[strlen(src_fname)]);
	memcpy(target_fname_location, target_fname, strlen(target_fname));
#endif
	add_attribute(header, &file_link_attrib->header, expansion_size);
#endif
	finish_header(header, ts);
	status = write_log((char *)header, header->length, sock, type);

	WARN_ON(!header);
#ifdef SOCKET_HEADER_ERROR						/* 5 June TJChoi : for handling error */
	if(header != &error_header)
        kfree(header);
#else
	kfree(header);
#endif
	return status;
}

#ifdef ABSENCE_STRLEN_USER
int log_fs_delete_file(STR_IN_USERAREA *stFilename, struct timespec ts,
			struct process_info proc_info, struct socket *sock)
#else
int log_fs_delete_file(char *fname, struct timespec ts, 
			struct process_info proc_info, struct socket *sock)
#endif
{
	int status = 1;
	char *fname_location;

#ifdef ABSENCE_STRLEN_USER
	size_t expansion_size = sizeof(struct progger_filenameAttribute) + stFilename->user_str_len;		/* added 0x1 for null terminated string */
#else
	size_t expansion_size = sizeof(struct progger_filenameAttribute) 
					+ strlen(fname);
#endif
	struct progger_filenameAttribute *fname_attrib;
	struct progger_header *header;

	header = new_header(PSCT_DIRNODE_DELETE, expansion_size, 
				(void **)&fname_attrib, proc_info, ts, true, sock);
#ifdef SOCKET_HEADER_ERROR						/* 5 June TJChoi : for handling error */
	if(fname_attrib != NULL)
	{
#ifdef ABSENCE_STRLEN_USER
		fname_attrib->filenameLength = stFilename->user_str_len;
#else
		fname_attrib->filenameLength = strlen(fname);
#endif
		fname_location = (char *)(&fname_attrib[1]);
#ifdef ABSENCE_STRLEN_USER
		memcpy(fname_location, stFilename->user_str, stFilename->user_str_len);
#else
		memcpy(fname_location, fname, strlen(fname));
#endif
		add_attribute(header, &fname_attrib->header, expansion_size);
		LOG_STR_BUF((char *)(&fname_attrib[1]), fname_attrib->filenameLength);
	}
#else
#ifdef ABSENCE_STRLEN_USER
	fname_attrib->filenameLength = stFilename->user_str_len;
#else
	fname_attrib->filenameLength = strlen(fname);
#endif

	fname_location = (char *)(&fname_attrib[1]);
#ifdef ABSENCE_STRLEN_USER
	memcpy(fname_location, stFilename->user_str, stFilename->user_str_len);
#else
	memcpy(fname_location, fname, strlen(fname));
#endif

	add_attribute(header, &fname_attrib->header, expansion_size);
#endif
	finish_header(header, ts);
	status = write_log((char *)header, header->length, sock, 
							PSCT_DIRNODE_DELETE);
	WARN_ON(!header);
#ifdef SOCKET_HEADER_ERROR						/* 5 June TJChoi : for handling error */
	if(header != &error_header)
        kfree(header);
#else
	kfree(header);
#endif
	return status;
}

#ifdef ABSENCE_STRLEN_USER
int log_fs_mkdir_rmdir(STR_IN_USERAREA *stPathname, enum progger_syscallTypes type,
				struct timespec ts, struct process_info proc_info, struct socket *sock)
#else
int log_fs_mkdir_rmdir(char *dir_path, enum progger_syscallTypes type, 
				struct timespec ts, 
			struct process_info proc_info, struct socket *sock)
#endif
{
	int status = 1;
        char *dir_location;

#ifdef ABSENCE_STRLEN_USER
    size_t expansion_size = sizeof(struct progger_filenameAttribute)+ stPathname->user_str_len;		/* TJ: added 0x1 for null terminated string */
#else
	size_t expansion_size = sizeof(struct progger_filenameAttribute)
                                        + strlen(dir_path);
#endif
	struct progger_filenameAttribute *fname_attrib;
	struct progger_header *header;

	header = new_header(type, expansion_size, 
					(void **)&fname_attrib, 
					proc_info, ts, true, sock);
#ifdef SOCKET_HEADER_ERROR						/* 5 June TJChoi : for handling error */
	if(fname_attrib != NULL)
	{
#ifdef ABSENCE_STRLEN_USER
		fname_attrib->filenameLength = stPathname->user_str_len;

		dir_location = (char *)(&fname_attrib[1]);
		memcpy(dir_location, stPathname->user_str, stPathname->user_str_len);
#else
		fname_attrib->filenameLength = strlen(dir_path);

		dir_location = (char *)(&fname_attrib[1]);
		memcpy(dir_location, dir_path, strlen(dir_path));
#endif
		add_attribute(header, &fname_attrib->header, expansion_size);
	}
#else
#ifdef ABSENCE_STRLEN_USER
	fname_attrib->filenameLength = stPathname->user_str_len;

	dir_location = (char *)(&fname_attrib[1]);
	memcpy(dir_location, stPathname->user_str, stPathname->user_str_len);
#else
	fname_attrib->filenameLength = strlen(dir_path);

	dir_location = (char *)(&fname_attrib[1]);
	memcpy(dir_location, dir_path, strlen(dir_path));
#endif

	add_attribute(header, &fname_attrib->header, expansion_size);
#endif
	finish_header(header, ts);

	LOG_STR_BUF((char *)(&fname_attrib[1]), fname_attrib->filenameLength);

        status = write_log((char *)header, header->length, sock, type);

        WARN_ON(!header);
#ifdef SOCKET_HEADER_ERROR						/* 5 June TJChoi : for handling error */
    if(header != &error_header)
        kfree(header);
#else
        kfree(header);
#endif
	return status;
}

