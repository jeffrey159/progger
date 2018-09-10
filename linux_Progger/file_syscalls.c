#include "./log.c"
#include "./progger_utils.h"
#include "definitions.h"	/* TJ to seperate codes according to defines.  April, 2018 */
#include "log.h"			/* TJ for log messages  April, 2018 */

static DEFINE_MUTEX(progger_current_mutex);

/*
 * Returns a new file descriptor if successful, which is is always guaranteed 
 * to be the lowest numbered unused descriptor. 
 * In case of failure, -1 is returned and the errno variale is set.
 *
 * asmlinkage long sys_open(const char __user *filename, 
 *                                              int flags, umode_t mode);
*/
void sys_open_handler(struct pt_regs *regs, bool has_ret, long fd, 
			struct timespec ts, 
			struct socket *sock, struct process_info proc_info)
{
        char *tmp;
	/* pathname of opened file, relative to syscall */
        const char __user *filename;
#ifdef ABSENCE_STRLEN_USER
    STR_IN_USERAREA *stK_FileName;
#else
	char *k_filename;
#endif
        int flags;      /* flags that have been set in the Open syscall */
        mode_t mode;    /* mode in which file has been opened */
	unsigned long inode_num;
        struct path *proc_path; /* CWD of current process */
        char *proc_pathname; /* string of CWD of current process */
	struct dentry *de;
	struct log_path *lp;
	char *pp;

        /* get the value of the parameters from the Open syscall */
        filename = (char __user *)regs->di;
        flags = (int)regs->si;
        mode = (mode_t)regs->dx;
#ifdef ABSENCE_STRLEN_USER
    stK_FileName = NULL;
    stK_FileName = stUstr_to_kspace(filename);

    if(stK_FileName == NULL)
    {
    	char* sTemp = NULL;
    	char sNoData[] = "No data from USER";
    	int iTempStringLen = strlen(sNoData);

    	stK_FileName = kmalloc(sizeof(STR_IN_USERAREA), GFP_KERNEL);
		if(stK_FileName == NULL){
			printk(KERN_ALERT "Progger: ERROR allocating memory\n");
			return;
		}

		stK_FileName->user_str=NULL;
		stK_FileName->user_str_len=iTempStringLen;

		/* Allocate space in memory for kernelspace string */
		stK_FileName->user_str = (char *)kmalloc(iTempStringLen, GFP_KERNEL);
		if (stK_FileName->user_str==NULL){
			printk(KERN_ALERT "Progger: ERROR allocating memory\n");
			kfree(stK_FileName);
			return;
		}

		memset(stK_FileName->user_str, 0, iTempStringLen);
		if(memcpy(stK_FileName->user_str, sNoData, iTempStringLen) != stK_FileName->user_str)
		{
			printk(KERN_ALERT "Progger: memcpy fails\n");
			kfree(stK_FileName->user_str);
			kfree(stK_FileName);
			return;
		}
		LOG_STR_USER(stK_FileName->user_str, stK_FileName->user_str_len);
    }
#else
	k_filename = ustr_to_kspace(filename);	
#endif

	/* get the inode of the file */
	/* https://www.kernel.org/doc/Documentation/filesystems/files.txt */
	inode_num = get_inode(fd);

#ifdef TJ_TEST																			/* 1 June TJChoi : don't be used */
	/* get CWD of process and construct the file's entire path */
	tmp = (char*)__get_free_page(GFP_TEMPORARY);
		
	spin_lock(&current->fs->lock);
		proc_path = &current->fs->pwd;		
		path_get(proc_path);
	spin_unlock(&current->fs->lock);

	de = proc_path->dentry;
	lp = kmalloc(sizeof(struct log_path), GFP_KERNEL);
	memset(lp, 0, sizeof(struct log_path));												/* 1 June TJChoi */

#if 0																					/* 1 June TJChoi : memory leakage */
	if(de == de->d_parent) {
		lp->mem = kmalloc(sizeof(char) * 2, GFP_KERNEL);
		lp->mem[0] = '/';
		lp->mem[1] = '\0';
		lp->name = lp->mem;			
		return;
	}
#endif
		
	lp->mem = kmalloc(sizeof(char) * PATH_MAX, GFP_KERNEL);
	memset(lp->mem, 0, PATH_MAX);														/* 1 June TJChoi */
	pp = lp->mem + PATH_MAX - 1;
	*pp = '\0';
	pp --;
	
	while(de != de->d_parent) {
		*pp = '/';
		pp -= de->d_name.len;
		memcpy(pp, de->d_name.name, de->d_name.len);
		pp --;
		de = de->d_parent;
	}
	*pp = '/';
	lp->name = pp;
#endif
	
#ifdef ABSENCE_STRLEN_USER
	#ifdef LOG_TO_KERNEL_BUF
	printk(KERN_ALERT "Progger:OPEN %s, %ld, %u\n", stK_FileName->user_str,
							fd, inode_num);
	#endif
	if (sock != NULL)
		log_fs_open(stK_FileName, fd, inode_num, (flags & O_CREAT), ts, proc_info, sock);
	kfree(stK_FileName->user_str);
	kfree(stK_FileName);
#else
	#ifdef LOG_TO_KERNEL_BUF
		printk(KERN_ALERT "Progger:OPEN %s, %ld, %u\n", k_filename,
						fd, inode_num);
	#endif
	if (sock != NULL)
		log_fs_open(k_filename, fd, inode_num, (flags & O_CREAT), ts, proc_info, sock);
	kfree(k_filename);
#endif
#ifdef TJ_TEST																			/* 1 June TJChoi : don't be used */
	kfree(lp->mem);
	kfree(lp);	
#endif
}

/* 
 * chmod() changes the permissions of the file specified whose pathname is 
 * given in path, which is dereferenced if it is a symbolic link. 
 * On success, zero is returned. 
 * On error, -1 is returned, and errno is set appropriately. 
 * 
 * asmlinkage long sys_chmod(const char __user *filename, umode_t mode); 
 */
void sys_chmod_handler(struct pt_regs *regs, struct timespec ts, 
			struct socket *sock, struct process_info proc_info)
{
	const char __user *filename;
	umode_t mode;
#ifdef ABSENCE_STRLEN_USER
    STR_IN_USERAREA *stK_FileName;
#else
	char *k_filename;
#endif

	filename = (const char __user *)regs->di;
	mode = (umode_t)regs->si;

#ifdef ABSENCE_STRLEN_USER
    stK_FileName = NULL;
    stK_FileName = stUstr_to_kspace(filename);
#if 1
    if(stK_FileName == NULL)
    {
    	char* sTemp = NULL;
    	char sNoData[] = "No data from USER";
    	int iTempStringLen = strlen(sNoData);

    	stK_FileName = kmalloc(sizeof(STR_IN_USERAREA), GFP_KERNEL);
		if(stK_FileName == NULL){
			printk(KERN_ALERT "Progger: ERROR allocating memory\n");
			return;
		}

		stK_FileName->user_str=NULL;
		stK_FileName->user_str_len=iTempStringLen;

		/* Allocate space in memory for kernelspace string */
		stK_FileName->user_str = (char *)kmalloc(iTempStringLen, GFP_KERNEL);
		if (stK_FileName->user_str==NULL){
			printk(KERN_ALERT "Progger: ERROR allocating memory\n");
			kfree(stK_FileName);
			return;
		}

		memset(stK_FileName->user_str, 0, iTempStringLen);
		if(memcpy(stK_FileName->user_str, sNoData, iTempStringLen) != stK_FileName->user_str)
		{
			printk(KERN_ALERT "Progger: memcpy fails\n");
			kfree(stK_FileName->user_str);
			kfree(stK_FileName);
			return;
		}
		LOG_STR_USER(stK_FileName->user_str, stK_FileName->user_str_len);
    }
#endif
	#ifdef LOG_TO_KERNEL_BUF
	printk(KERN_ALERT "Progger:CHMOD %s\n", stK_FileName->user_str);
	#endif
	if (sock != NULL)
		log_fs_change_permissions(stK_FileName, -1, -1, ts, proc_info, sock);

	kfree(stK_FileName->user_str);
	kfree(stK_FileName);
#else
	k_filename = ustr_to_kspace(filename);
	#ifdef LOG_TO_KERNEL_BUF
	printk(KERN_ALERT "Progger:CHMOD %s\n", k_filename);
	#endif
	if (sock != NULL)
		log_fs_change_permissions(k_filename, -1, -1, ts, proc_info, sock);
	kfree(k_filename);
#endif
}

/* 
 * fchmod() changes the permissions of the file referred to by the open fd. 
 * 
 * asmlinkage long sys_fchmod(unsigned int fd, umode_t mode); 
 */
void sys_fchmod_handler(struct pt_regs *regs, struct timespec ts, 
			struct socket *sock, struct process_info proc_info)
{
	unsigned int fd, inode_num;
        umode_t mode;

	fd = (unsigned int)regs->di;
        mode = (umode_t)regs->si;

	inode_num = get_inode(fd);
	
	#ifdef LOG_TO_KERNEL_BUF
		printk(KERN_ALERT "Progger:CHMOD %ld, %u\n", fd, inode_num);
	#endif	
	if (sock != NULL)
#ifdef ABSENCE_STRLEN_USER
	{
		STR_IN_USERAREA* stKstr = NULL;
		char achStr[]="N/A";

		stKstr = kmalloc(sizeof(STR_IN_USERAREA), GFP_KERNEL);
		if(stKstr == NULL){
			printk(KERN_ALERT "Progger: ERROR allocating memory\n");
#if 0
			error send
#endif
			return;
		}
		stKstr->user_str = achStr;
		stKstr->user_str_len = strlen(achStr);
		log_fs_change_permissions(stKstr, fd, inode_num, ts, proc_info, sock);
		kfree(stKstr);
	}
#else
		log_fs_change_permissions("N/A", fd, inode_num, ts, proc_info,
									 sock);
#endif
}

/* 
 * chown() changes the ownership of the file specified by path, which is 
 * dereferenced if it is a symbolic link.
 * lchown() behaves like chown() and uses the same parameters, but does not
 * dereference links.
 * On success, zero is returned. 
 * On error, -1 is returned, and errno is set appropriately. 
 *
 * asmlinkage long sys_chown(const char __user *filename, uid_t user, 
 * 							gid_t group); 
 */
void sys_chown_handler(struct pt_regs *regs, long syscall_id, 
				struct timespec ts, struct socket *sock, 
						struct process_info proc_info)
{
	const char __user *filename;
	uid_t owner;
	gid_t group;
#ifdef ABSENCE_STRLEN_USER
    STR_IN_USERAREA *stK_FileName;
#else
	char *k_filename;
#endif

	filename = (const char __user *)regs->di;
	owner = (uid_t)regs->si;
	group = (gid_t)regs->dx;

#ifdef ABSENCE_STRLEN_USER
    stK_FileName = NULL;
    stK_FileName = stUstr_to_kspace(filename);
#if 1
    if(stK_FileName == NULL)
    {
    	char* sTemp = NULL;
    	char sNoData[] = "No data from USER";
    	int iTempStringLen = strlen(sNoData);

    	stK_FileName = kmalloc(sizeof(STR_IN_USERAREA), GFP_KERNEL);
		if(stK_FileName == NULL){
			printk(KERN_ALERT "Progger: ERROR allocating memory\n");
			return;
		}

		stK_FileName->user_str=NULL;
		stK_FileName->user_str_len=iTempStringLen;

		/* Allocate space in memory for kernelspace string */
		stK_FileName->user_str = (char *)kmalloc(iTempStringLen, GFP_KERNEL);
		if (stK_FileName->user_str==NULL){
			printk(KERN_ALERT "Progger: ERROR allocating memory\n");
			kfree(stK_FileName);
			return;
		}

		memset(stK_FileName->user_str, 0, iTempStringLen);
		if(memcpy(stK_FileName->user_str, sNoData, iTempStringLen) != stK_FileName->user_str)
		{
			printk(KERN_ALERT "Progger: memcpy fails\n");
			kfree(stK_FileName->user_str);
			kfree(stK_FileName);
			return;
		}
		LOG_STR_USER(stK_FileName->user_str, stK_FileName->user_str_len);
    }
#endif
	#ifdef LOG_TO_KERNEL_BUF
   printk(KERN_ALERT "Progger:CHOWN %s\n", stK_FileName->user_str);
	#endif
    if (sock != NULL)
    	log_fs_change_owner(stK_FileName, -1, -1, owner, ts, proc_info, sock);
	WARN_ON(!stK_FileName->user_str);
	kfree(stK_FileName->user_str);
	kfree(stK_FileName);
#else
	k_filename = ustr_to_kspace(filename);

	#ifdef LOG_TO_KERNEL_BUF
    printk(KERN_ALERT "Progger:CHOWN %s\n", k_filename);
	#endif
    if (sock != NULL)
		log_fs_change_owner(k_filename, -1, -1, owner, ts, proc_info, 
										sock);
	WARN_ON(!k_filename);
	kfree(k_filename);
#endif
}

/*
 * fchown() changes the ownership of the file referred to by the open fd. 
 *  
 * asmlinkage long sys_fchown(unsigned int fd, uid_t user, gid_t group);
 */
void sys_fchown_handler(struct pt_regs *regs, struct timespec ts, 
			struct socket *sock, struct process_info proc_info)
{
	unsigned int fd, inode_num;
	uid_t owner;
	gid_t group;	

	fd = (unsigned int)regs->di;
	owner = (uid_t)regs->si;
        group = (gid_t)regs->dx;

	inode_num = get_inode(fd);

        #ifdef LOG_TO_KERNEL_BUF
		printk(KERN_ALERT "Progger:CHOWN %ld, %u\n", fd, inode_num);
        #endif
	if (sock != NULL)
#ifdef ABSENCE_STRLEN_USER
	{
		{
			STR_IN_USERAREA* stKstr = NULL;
			char achStr[]="N/A";

			stKstr = kmalloc(sizeof(STR_IN_USERAREA), GFP_KERNEL);
			if(stKstr == NULL){
				printk(KERN_ALERT "Progger: ERROR allocating memory\n");
	#if 0
				error send
	#endif
				return;
			}
			stKstr->user_str = achStr;
			stKstr->user_str_len = strlen(achStr);
			log_fs_change_owner(stKstr, fd, inode_num, owner, ts, proc_info, sock);
			kfree(stKstr);
		}
	}
#else
                log_fs_change_owner("N/A", fd, inode_num, owner, ts, proc_info,
									 sock);
#endif
}

/*
 * fchownat() changes ownership of a file relative to directory fd.
 * On success, fchownat() returns 0. 
 * On error, -1 is returned and errno is set to indicate the error.
 * 
 * If pathname is relative and dirfd is special value AT_FDCWD, pathname is 
 * interpreted relative to CWD of calling process, like with chown
 *
 * If pathname is absolute, dirfd is ignored
 *
 * asmlinkage long sys_fchownat(int dfd, const char __user *filename, 
 * 				uid_t user, gid_t group, int flag); 
 */
void sys_fchownat_handler(struct pt_regs *regs, struct timespec ts, 
			struct socket *sock, struct process_info proc_info)
{
	int dirfd;
	const char __user *usr_fname;
#ifdef ABSENCE_STRLEN_USER
    STR_IN_USERAREA *stK_FileName;
#else
    char *k_fname;
#endif
	uid_t user;
	gid_t group;
	char *tmp;
	char *pathname;
	struct file *file;
	struct path *path;		

	dirfd = (int)regs->di;
	usr_fname = (char __user *)regs->si;
	user = (uid_t)regs->dx;

#ifdef ABSENCE_STRLEN_USER
    stK_FileName = NULL;
    stK_FileName = stUstr_to_kspace(usr_fname);
#if 1
    if(stK_FileName == NULL)
    {
    	char* sTemp = NULL;
    	char sNoData[] = "No data from USER";
    	int iTempStringLen = strlen(sNoData);

    	stK_FileName = kmalloc(sizeof(STR_IN_USERAREA), GFP_KERNEL);
		if(stK_FileName == NULL){
			printk(KERN_ALERT "Progger: ERROR allocating memory\n");
			return;
		}

		stK_FileName->user_str=NULL;
		stK_FileName->user_str_len=iTempStringLen;

		/* Allocate space in memory for kernelspace string */
		stK_FileName->user_str = (char *)kmalloc(iTempStringLen, GFP_KERNEL);
		if (stK_FileName->user_str==NULL){
			printk(KERN_ALERT "Progger: ERROR allocating memory\n");
			kfree(stK_FileName);
			return;
		}

		memset(stK_FileName->user_str, 0, iTempStringLen);
		if(memcpy(stK_FileName->user_str, sNoData, iTempStringLen) != stK_FileName->user_str)
		{
			printk(KERN_ALERT "Progger: memcpy fails\n");
			kfree(stK_FileName->user_str);
			kfree(stK_FileName);
			return;
		}
		LOG_STR_USER(stK_FileName->user_str, stK_FileName->user_str_len);
    }
#endif
	// TODO handle filepath relative to dirfd
    LOG_STR_USER(stK_FileName->user_str, stK_FileName->user_str_len);
#else
    k_fname = ustr_to_kspace(usr_fname);
    // TODO handle filepath relative to dirfd
	printk(KERN_ALERT "Progger: FCHOWNAT %s\n", k_fname);
#endif

	/* pathname is relative and dirfd is special value AT_FDCWD, so 
	 * proceed like with sys_chown
	if (dirfd == AT_FDCWD) {
		printk(KERN_ALERT "Progger: FCHOWNAT dirfd == AT_FDCWD\n");
		log_fs_change_owner(k_fname, -1, -1, user, ts, proc_info, 
									sock);
		return;
	}*/

	// get the pathname for dirfd
	spin_lock(&current->files->file_lock);
	file = fcheck_files(current->files, dirfd);
	if (!file) {
		spin_unlock(&current->files->file_lock);
		printk(KERN_ALERT "Progger: FCHOWNAT|!file\n");
		return -ENOENT;
	}
	path = &file->f_path;
	path_get(path);
	spin_unlock(&current->files->file_lock);

	tmp = (char *)__get_free_page(GFP_TEMPORARY);
	if (!tmp) {
		printk(KERN_ALERT "Progger: FCHOWNAT|!tmp\n");
    		path_put(path);
		return -ENOMEM;
	}
	
	pathname = d_path(path, tmp, PAGE_SIZE);
	path_put(path);

	if (IS_ERR(pathname)) {
		printk(KERN_ALERT "Progger: FCHOWNAT|error pathname\n");
 		free_page((unsigned long)tmp);
		return PTR_ERR(pathname);
	}

#ifdef LOG_SYSCALL
	printk(KERN_ALERT "Progger: fchownat %s\n", pathname);
#endif

#ifdef ABSENCE_STRLEN_USER
	kfree(stK_FileName->user_str);
	kfree(stK_FileName);
#else
	kfree(k_fname);
#endif
	free_page((unsigned long)tmp);
	kfree(pathname);
}

/*
 * pipe() creates a unidirectional data channel that can be used for 
 * interprocess communication. 
 * Array pipefd is used to return two fd referring to the ends of the pipe. 
 * pipefd[0] refers to read end and pipefd[1] refers to the write end of pipe.
 *
 * asmlinkage long sys_pipe(int __user *pipefd);
 */
void sys_pipe_handler(struct pt_regs *regs, struct timespec ts, 
			struct socket *sock, struct process_info proc_info)
{
        int __user *pipefd;
	unsigned int inode_rd, inode_wr;
        int is_sock;

	pipefd = (int __user *)(regs->di);

	inode_rd = get_inode(pipefd[0]);
	inode_wr = get_inode(pipefd[1]);

        is_sock = is_socket(current->files, pipefd[0]);
        if (is_sock == ENOENT) {
	        printk(KERN_ALERT "Progger: PIPE Error Read:ENOENT fd %d\n",
                                                                pipefd[0]);
                return;
        }
	
        /* Determine if the write fd is a file or socket descriptor */
        is_sock = is_socket(current->files, pipefd[1]);
        if (is_sock == ENOENT) {
	        printk(KERN_ALERT
                                "Progger: PIPE error Write:ENOENT fd %d\n",
                                                              pipefd[1]);
                return;
        }
	
        #ifdef LOG_TO_KERNEL_BUF
	printk(KERN_ALERT "Progger:PIPE\n");
	#endif

	if (sock != NULL) {
        	if (is_sock)
                	log_handle_duplicate(pipefd[0], inode_rd, 
						pipefd[1], inode_wr, 
						PHT_SOCKET, ts, proc_info, 
									sock);
        	else
                	log_handle_duplicate(pipefd[0], inode_rd, 
                                                pipefd[1], inode_wr, 
                                                PHT_FILE, ts, proc_info, sock);
	}
}

/*
 * Function that handles the callback function for a SYS_CLOSE syscall. 
 *
 * close() closes a file descriptor, so that it no longer refers to any file 
 * and may be reused.
 * close() returns zero on success.  On error, -1 is returned, and errno
 * is set appropriately.
 *
 * The value of the closed file descriptor is fetched from the original 
 * syscall. The close syscall is logged appropriately depending on whether it
 * is a socket syscall or file syscall.
 *
 * asmlinkage long sys_close(unsigned int fd);
 */
void sys_close_handler(struct pt_regs *regs, struct timespec ts, 
			struct socket *sock, struct process_info proc_info)
{
        unsigned int fd, inode_num;
        int is_sock;

	/* Get the first (and only) argument from the Close syscall */
        fd = (unsigned int)regs->di;

	inode_num = get_inode(fd);

        /* Determine if the fd is a file or socket descriptor */
        is_sock = is_socket(current->files, fd);
        if (is_sock == ENOENT) {
       		printk(KERN_ALERT "Progger: ERROR Close:ENOENT fd %d\n", fd);
                return;
        }
	// NOTE: only for file close, not socket so far
	#ifdef LOG_TO_KERNEL_BUF
	        printk(KERN_ALERT "Progger:CLOSE %ld, %u\n", fd, inode_num);
        #endif
	if (sock != NULL)                
		log_fs_close(fd, inode_num, ts, proc_info, sock);
}

/*
 * sendfile() copies data between one fd to another. Because this copying is 
 * done within the kernel, sendfile() is more efficient than the combination 
 * of read(2) and write(2), which would require transferring data to and from 
 * user space.
 *
 * asmlinkage long sys_sendfile(int out_fd, int in_fd, off_t __user *offset, 
 *                                                              size_t count);
 */
void sys_sendfile_handler(struct pt_regs *regs, struct timespec ts, 
			struct socket *sock, struct process_info proc_info)
{
        int out_fd, in_fd;
	unsigned int inode_out, inode_in;
        
        size_t count;
        int is_sock;

        out_fd = (int)regs->di;
        in_fd = (int)regs->si;
        count = (size_t)regs->r10;
        
	inode_out = get_inode(out_fd);
	inode_in = get_inode(in_fd);
	
        #ifdef LOG_TO_KERNEL_BUF
		printk(KERN_ALERT "Progger:SENDFILE\n");
     	#endif
	if (sock != NULL) {        
		log_fs_read_write(PSCT_FILE_READ, out_fd, inode_out, 0, 0, 
					ts, proc_info, sock);
		log_fs_read_write(PSCT_FILE_WRITE, in_fd, inode_in, 0, 0, ts, 
					proc_info, sock);
	}
}

/* asmlinkage long sys_rename(const char __user *oldname, 
 *                                              const char __user *newname);
 *
 * link() creates a new link (also known as a hard link) to an existing file.
 * If newpath exists it will not be overwritten.
 * On success, zero is returned. O
 * On error, -1 is returned, and errno is set appropriately.
 * aemlinkage long sys_link(const char __user *oldname, 
 *                                              const char __user *newname);
 */
void sys_rename_link_handler(struct pt_regs *regs, 
			enum progger_syscallTypes type,  struct timespec ts, 
			struct socket *sock, struct process_info proc_info)
{
        char __user *oldname;
        char __user *newname;
#ifdef ABSENCE_STRLEN_USER
    STR_IN_USERAREA *stK_OldFileName;
    STR_IN_USERAREA *stK_NewFileName;
#else
    char *k_oldname;
    char *k_newname;
#endif
        oldname = (char __user *)regs->di;
        newname = (char __user *)regs->si;

#ifdef ABSENCE_STRLEN_USER
    stK_OldFileName = NULL;
    stK_NewFileName = NULL;
    stK_OldFileName = stUstr_to_kspace(oldname);

    if(stK_OldFileName == NULL)
    {
    	char* sTemp = NULL;
    	char sNoData[] = "No data from USER";
    	int iTempStringLen = strlen(sNoData);

    	stK_OldFileName = kmalloc(sizeof(STR_IN_USERAREA), GFP_KERNEL);
		if(stK_OldFileName == NULL){
			printk(KERN_ALERT "Progger: ERROR allocating memory\n");
			return;
		}

		stK_OldFileName->user_str=NULL;
		stK_OldFileName->user_str_len=iTempStringLen;

		/* Allocate space in memory for kernelspace string */
		stK_OldFileName->user_str = (char *)kmalloc(iTempStringLen, GFP_KERNEL);
		if (stK_OldFileName->user_str==NULL){
			printk(KERN_ALERT "Progger: ERROR allocating memory\n");
			kfree(stK_OldFileName);
			return;
		}

		memset(stK_OldFileName->user_str, 0, iTempStringLen);
		if(memcpy(stK_OldFileName->user_str, sNoData, iTempStringLen) != stK_OldFileName->user_str)
		{
			printk(KERN_ALERT "Progger: memcpy fails\n");
			kfree(stK_OldFileName->user_str);
			kfree(stK_OldFileName);
			return;
		}
		LOG_STR_USER(stK_OldFileName->user_str, stK_OldFileName->user_str_len);
    }

    stK_NewFileName = stUstr_to_kspace(newname);

    if(stK_NewFileName == NULL)
    {
    	char* sTemp = NULL;
    	char sNoData[] = "No data from USER";
    	int iTempStringLen = strlen(sNoData);

    	stK_NewFileName = kmalloc(sizeof(STR_IN_USERAREA), GFP_KERNEL);
		if(stK_NewFileName == NULL){
			printk(KERN_ALERT "Progger: ERROR allocating memory\n");
			return;
		}

		stK_NewFileName->user_str=NULL;
		stK_NewFileName->user_str_len=iTempStringLen;

		/* Allocate space in memory for kernelspace string */
		stK_NewFileName->user_str = (char *)kmalloc(iTempStringLen, GFP_KERNEL);
		if (stK_NewFileName->user_str==NULL){
			printk(KERN_ALERT "Progger: ERROR allocating memory\n");
			kfree(stK_NewFileName);
			return;
		}

		memset(stK_NewFileName->user_str, 0, iTempStringLen);
		if(memcpy(stK_NewFileName->user_str, sNoData, iTempStringLen) != stK_NewFileName->user_str)
		{
			printk(KERN_ALERT "Progger: memcpy fails\n");
			kfree(stK_NewFileName->user_str);
			kfree(stK_NewFileName);
			return;
		}
		LOG_STR_USER(stK_NewFileName->user_str, stK_NewFileName->user_str_len);
    }

#ifdef LOG_TO_KERNEL_BUF
    printk(KERN_ALERT "Progger:RENAME %s, %s\n", stK_OldFileName->user_str, stK_NewFileName->user_str);
#endif
	if (sock != NULL)
		log_fs_rename_hardlink(PSCT_DIRNODE_RENAME, stK_OldFileName, stK_NewFileName, ts, proc_info, sock);
	kfree(stK_OldFileName->user_str);
	kfree(stK_OldFileName);
	kfree(stK_NewFileName->user_str);
	kfree(stK_NewFileName);
#else
    k_oldname = ustr_to_kspace(oldname);
    k_newname = ustr_to_kspace(newname);
#ifdef LOG_TO_KERNEL_BUF
		 printk(KERN_ALERT "Progger:RENAME %s, %s\n", k_oldname,
						k_newname);
#endif
	if (sock != NULL)
		log_fs_rename_hardlink(PSCT_DIRNODE_RENAME, k_oldname, 
						k_newname, ts, proc_info,									 sock);
	kfree(k_oldname);
	kfree(k_newname);
#endif
}

/*
 * unlink() deletes a name from the file system.
 * asmlinkage long sys_unlink(const char __user *pathname);
 *
 * unlinkat - remove a directory entry relative to a directory file descriptor
 * If pathname is relative, 
 *      it is interpreted relative to the dir referred to by dirfd 
 *      (rather than relative to cwd of calling process)
 * If pathname is relative AND dirfd is special value AT_FDCWD,
 *      pathname is interpreted relative to cwd of the calling process
 *
 * int unlinkat(int dirfd, const char *pathname, int flags)
 */
void sys_unlink_handler(struct pt_regs *regs, long syscall_id, 
				struct timespec ts, struct socket *sock, 
						struct process_info proc_info)
{
	const char __user *pathname;
#ifdef ABSENCE_STRLEN_USER
    STR_IN_USERAREA *stK_PathName;
#else
    char *k_pathname;
#endif
	int dirfd, flags;

	dirfd = flags = -1;

	if (syscall_id == __NR_unlink)	
		pathname = (const char __user *)regs->di;
	else {
		dirfd = (int)regs->di;
		pathname = (const char __user *)regs->si;
		flags = (int)regs->dx;		
	}
#ifdef ABSENCE_STRLEN_USER
	stK_PathName = NULL;
	stK_PathName = stUstr_to_kspace(pathname);

    if(stK_PathName == NULL)
    {
    	char* sTemp = NULL;
    	char sNoData[] = "No data from USER";
    	int iTempStringLen = strlen(sNoData);

    	stK_PathName = kmalloc(sizeof(STR_IN_USERAREA), GFP_KERNEL);
		if(stK_PathName == NULL){
			printk(KERN_ALERT "Progger: ERROR allocating memory\n");
			return;
		}

		stK_PathName->user_str=NULL;
		stK_PathName->user_str_len=iTempStringLen;

		/* Allocate space in memory for kernelspace string */
		stK_PathName->user_str = (char *)kmalloc(iTempStringLen, GFP_KERNEL);
		if (stK_PathName->user_str==NULL){
			printk(KERN_ALERT "Progger: ERROR allocating memory\n");
			kfree(stK_PathName);
			return;
		}

		memset(stK_PathName->user_str, 0, iTempStringLen);
		if(memcpy(stK_PathName->user_str, sNoData, iTempStringLen) != stK_PathName->user_str)
		{
			printk(KERN_ALERT "Progger: memcpy fails\n");
			kfree(stK_PathName->user_str);
			kfree(stK_PathName);
			return;
		}
		LOG_STR_USER(stK_PathName->user_str, stK_PathName->user_str_len);
    }
#ifdef LOG_TO_KERNEL_BUF
	printk(KERN_ALERT "Progger:CHOWN %s\n", stK_PathName->user_str);
#endif
	if (sock != NULL)
		log_fs_delete_file(stK_PathName, ts, proc_info, sock);

	kfree(stK_PathName->user_str);
	kfree(stK_PathName);
#else
    k_pathname = ustr_to_kspace(pathname);
#ifdef LOG_TO_KERNEL_BUF
	printk(KERN_ALERT "Progger:CHOWN %s\n", k_pathname);
#endif
	if (sock != NULL)        
		log_fs_delete_file(k_pathname, ts, proc_info, sock);
		
	kfree(k_pathname);
#endif
}

/* 
 * symlink() creates a symbolic link named newpath which contains the string oldpath. 
 * On success, zero is returned. 
 * On error, -1 is returned, and errno is set appropriately. 
 *
 * asmlinkage long sys_symlink(const char __user *old, const char __user *new)
 */
void sys_symlink_handler(struct pt_regs *regs, struct timespec ts, 
			struct socket *sock, struct process_info proc_info)
{   
	const char __user *old;
	const char __user *new;
#ifdef ABSENCE_STRLEN_USER
    STR_IN_USERAREA *stK_OldPathName;
    STR_IN_USERAREA *stK_NewPathName;
#else
    char *k_old;
    char *k_new;
#endif
 
	old = (const char __user *)regs->di;
	new = (const char __user *)regs->si;
#ifdef ABSENCE_STRLEN_USER
	stK_OldPathName = NULL;
	stK_NewPathName = NULL;
    stK_OldPathName = stUstr_to_kspace(old);

    if(stK_OldPathName == NULL)
    {
    	char* sTemp = NULL;
    	char sNoData[] = "No data from USER";
    	int iTempStringLen = strlen(sNoData);

    	stK_OldPathName = kmalloc(sizeof(STR_IN_USERAREA), GFP_KERNEL);
		if(stK_OldPathName == NULL){
			printk(KERN_ALERT "Progger: ERROR allocating memory\n");
			return;
		}

		stK_OldPathName->user_str=NULL;
		stK_OldPathName->user_str_len=iTempStringLen;

		/* Allocate space in memory for kernelspace string */
		stK_OldPathName->user_str = (char *)kmalloc(iTempStringLen, GFP_KERNEL);
		if (stK_OldPathName->user_str==NULL){
			printk(KERN_ALERT "Progger: ERROR allocating memory\n");
			kfree(stK_OldPathName);
			return;
		}

		memset(stK_OldPathName->user_str, 0, iTempStringLen);
		if(memcpy(stK_OldPathName->user_str, sNoData, iTempStringLen) != stK_OldPathName->user_str)
		{
			printk(KERN_ALERT "Progger: memcpy fails\n");
			kfree(stK_OldPathName->user_str);
			kfree(stK_OldPathName);
			return;
		}
		LOG_STR_USER(stK_OldPathName->user_str, stK_OldPathName->user_str_len);
    }
    stK_NewPathName = stUstr_to_kspace(new);

    if(stK_NewPathName == NULL)
    {
    	char* sTemp = NULL;
    	char sNoData[] = "No data from USER";
    	int iTempStringLen = strlen(sNoData);

    	stK_NewPathName = kmalloc(sizeof(STR_IN_USERAREA), GFP_KERNEL);
		if(stK_NewPathName == NULL){
			printk(KERN_ALERT "Progger: ERROR allocating memory\n");
			return;
		}

		stK_NewPathName->user_str=NULL;
		stK_NewPathName->user_str_len=iTempStringLen;

		/* Allocate space in memory for kernelspace string */
		stK_NewPathName->user_str = (char *)kmalloc(iTempStringLen, GFP_KERNEL);
		if (stK_NewPathName->user_str==NULL){
			printk(KERN_ALERT "Progger: ERROR allocating memory\n");
			kfree(stK_NewPathName);
			return;
		}

		memset(stK_NewPathName->user_str, 0, iTempStringLen);
		if(memcpy(stK_NewPathName->user_str, sNoData, iTempStringLen) != stK_NewPathName->user_str)
		{
			printk(KERN_ALERT "Progger: memcpy fails\n");
			kfree(stK_NewPathName->user_str);
			kfree(stK_NewPathName);
			return;
		}
		LOG_STR_USER(stK_NewPathName->user_str, stK_NewPathName->user_str_len);
    }
#ifdef LOG_TO_KERNEL_BUF
    printk(KERN_ALERT "Progger:SYMLINK %s, %s\n", stK_OldPathName->user_str, stK_NewPathName->user_str);
#endif
    if (sock != NULL)
        	log_fs_link(stK_OldPathName, stK_NewPathName, ts, proc_info, sock);
	kfree(stK_OldPathName->user_str);
	kfree(stK_OldPathName);
	kfree(stK_NewPathName->user_str);
	kfree(stK_NewPathName);
#else
	k_old = ustr_to_kspace(old);
	k_new = ustr_to_kspace(new);
	#ifdef LOG_TO_KERNEL_BUF
	printk(KERN_ALERT "Progger:SYMLINK %s, %s\n", k_old, k_new);
	#endif
    if (sock != NULL)
    	log_fs_link(k_old, k_new, ts, proc_info, sock);
	kfree(k_old);
	kfree(k_new);
#endif
}

/*
 * asmlinkage long sys_write(unsigned int fd, char __user *buf, size_t count);
 *
 * asmlinkage long sys_read(unsigned int fd, char __user *buf, size_t count);
 *  
 * asmlinkage long sys_pread64(unsigned int fd, const char __user *buf, 
 *                                              size_t count, loff_t pos);
 *
 * asmlinkage long sys_pwrite64(unsigned int fd, const char __user *buf, 
 *                                              size_t count, loff_t pos);
 */
void sys_read_write_handler(struct pt_regs *regs, 
			enum progger_syscallTypes type, long syscall_id, 
				struct timespec ts, struct socket *sock, 
						struct process_info proc_info)
{
        int fd;
        size_t count;
        loff_t pos;
	int is_sock;
	unsigned long inode_num;
	
        fd = (int)regs->di;
	pos = -1;
        count = (size_t)regs->dx;
	if (syscall_id == __NR_pread64 || syscall_id == __NR_pwrite64)
		pos = (loff_t)regs->r10;

	inode_num = get_inode(fd);

        is_sock = is_socket(current->files, fd);
        if (is_sock == ENOENT) {
       		printk(KERN_ALERT "Progger: ERROR Read:ENOENT fd %d\n", fd);
                return;
        }
                
	#ifdef LOG_TO_KERNEL_BUF
		printk(KERN_ALERT "Progger:RDWR %ld, %u\n", fd, inode_num);
	#endif
        if (sock != NULL)
                log_fs_read_write(type, fd, inode_num, count, pos, ts, 
							proc_info, sock);
}

/* 
 * asmlinkage long sys_mkdir(const char __user *pathname, umode_t mode);
 * asmlinkage long sys_rmdir(const char __user *pathname);
 */
void sys_mkdir_rmdir_handler(struct pt_regs *regs, 
				enum progger_syscallTypes type, 
				struct timespec ts, struct socket *sock, 
						struct process_info proc_info)
{
        const char __user *pathname;
#ifdef ABSENCE_STRLEN_USER
    STR_IN_USERAREA *stK_PathName;

    pathname = (const char __user *)regs->di;

    stK_PathName = NULL;
    stK_PathName = stUstr_to_kspace(pathname);

    if(stK_PathName == NULL)
    {
    	char* sTemp = NULL;
    	char sNoData[] = "No data from USER";
    	int iTempStringLen = strlen(sNoData);

    	stK_PathName = kmalloc(sizeof(STR_IN_USERAREA), GFP_KERNEL);
		if(stK_PathName == NULL){
			printk(KERN_ALERT "Progger: ERROR allocating memory\n");
			return;
		}

		stK_PathName->user_str=NULL;
		stK_PathName->user_str_len=iTempStringLen;

		/* Allocate space in memory for kernelspace string */
		stK_PathName->user_str = (char *)kmalloc(iTempStringLen, GFP_KERNEL);
		if (stK_PathName->user_str==NULL){
			printk(KERN_ALERT "Progger: ERROR allocating memory\n");
			kfree(stK_PathName);
			return;
		}

		memset(stK_PathName->user_str, 0, iTempStringLen);
		if(memcpy(stK_PathName->user_str, sNoData, iTempStringLen) != stK_PathName->user_str)
		{
			printk(KERN_ALERT "Progger: memcpy fails\n");
			kfree(stK_PathName->user_str);
			kfree(stK_PathName);
			return;
		}
		LOG_STR_USER(stK_PathName->user_str, stK_PathName->user_str_len);
    }
#ifdef LOG_TO_KERNEL_BUF
	if (type == PSCT_DIRNODE_CREATE)
		printk(KERN_ALERT "Progger:MKDIR %s\n", stK_PathName->user_str);
	else
		printk(KERN_ALERT "Progger:RMDIR %s\n", stK_PathName->user_str);
#endif
	if (sock != NULL)
		log_fs_mkdir_rmdir(stK_PathName, type, ts, proc_info, sock);

	kfree(stK_PathName->user_str);
	kfree(stK_PathName);
#else
    char *k_pathname;

    pathname = (const char __user *)regs->di;
    k_pathname = ustr_to_kspace(pathname);

    #ifdef LOG_TO_KERNEL_BUF
	if (type == PSCT_DIRNODE_CREATE)
		printk(KERN_ALERT "Progger:MKDIR %s\n", k_pathname);
	else
		printk(KERN_ALERT "Progger:RMDIR %s\n", k_pathname);
	#endif
	if (sock != NULL)                
		log_fs_mkdir_rmdir(k_pathname, type, ts, proc_info, sock);
	
	kfree(k_pathname);
#endif
}

/* 
 * dup() syscall creates a copy of the fd oldfd, using the lowest-numbered 
 * unused file descriptor for the new descriptor.
 * After a successful return, the old and new file descriptors may be used 
 * interchangeably.
 * 
 * The dup2() system call performs the same task as dup(), but instead
 * of using the lowest-numbered unused file descriptor, it uses the fd
 * specified in newfd. 
 *
 * asmlinkage long sys_dup(unsigned int fildes);
 * asmlinkage long sys_dup2(unsigned int oldfd, unsigned int newfd);
 */
void sys_dup_handler(struct pt_regs *regs, long syscall_id, struct timespec ts, 
			struct socket *sock, struct process_info proc_info)
{
        unsigned int old_fd, new_fd;
	unsigned long inode_old, inode_new;
	int is_sock;

        old_fd = (unsigned int)regs->di;
	new_fd = inode_new = -1;

	inode_old = get_inode(old_fd);

	if (syscall_id == __NR_dup2) {
		new_fd = (unsigned int)regs->si;
		inode_new = get_inode(new_fd);
	}

	is_sock = is_socket(current->files, old_fd);
        if (is_sock == ENOENT) {
                printk(KERN_ALERT "Progger: DUP/2 Error fd %d\n", old_fd);
                return;
        }

        if (is_sock) {
        	#ifdef LOG_TO_KERNEL_BUF
			printk(KERN_ALERT "Progger:DUP sock\n");
		#endif
		if (sock != NULL)
			log_handle_duplicate(old_fd, inode_old, new_fd, 
						inode_new, PHT_SOCKET, ts, 
							proc_info, sock);
	} 
	else {
		#ifdef LOG_TO_KERNEL_BUF
                        printk(KERN_ALERT "Progger:DUP file\n");
                #endif
		if (sock != NULL)
			log_handle_duplicate(old_fd, inode_old, new_fd, 
                                                inode_new, PHT_FILE, ts, 
                                                        proc_info, sock);
	}
}
