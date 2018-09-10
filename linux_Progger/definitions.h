#ifndef _DEFINITIONS_H
#define _DEFINITIONS_H


/* TJ for using strncpy_from_user instead of strlen_user
 * because of absence of strlen_user after kernel version 4.13.1
 * date: 10, April, 2018 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0))
#define ABSENCE_STRLEN_USER
#endif

#define SOCKET_HEADER_ERROR						/* 2 June TJChoi : for handling error */
#define MODULE_PARAM							/* 12 June TJChoi : for module param */


#endif
