/*
 * log.h
 *
 *  Created on: 23/04/2018
 *      Author: tj
 */

#ifndef LOG_H_
#define LOG_H_

#define USERSTR 0x0
#define BUFSTR 0x0
#define PKTSTR 0x1

#define LOG_SYSCALL					/* added by TJ for reducing the amount of logs */

#define LOG_STR_USER(str, len) if( USERSTR==0x1 ) { \
	printk(KERN_ALERT "Progger USERSTR: %s:%d: %s, len=%d\n", __FUNCTION__,__LINE__, str, len); \
}

#define LOG_STR_BUF(str, len) if( BUFSTR==0x1 ) { \
	printk(KERN_ALERT "Progger BUFSTR: %s:%d: %s, len=%d\n", __FUNCTION__,__LINE__, str, len); \
}

#define LOG_STR_PKT(str, len) if( PKTSTR==0x1 ) { \
	printk(KERN_ALERT "Progger PKTSTR: %s:%d: %s, len=%d\n", __FUNCTION__,__LINE__, str, len); \
}

/*#ifdef MODULE_PARAM										/* 12 June TJChoi : for module param */
static unsigned long long dHostId;					/* 14 June TJChoi : for HostId */

#endif /* LOG_H_ */
