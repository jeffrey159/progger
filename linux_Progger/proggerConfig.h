#pragma once

#define PROGGER_PREF
#define PROGGER_LINUX

/*
 * CONFIGURATION FOR LAYER X BELOW 
 */
/* Redis server configuration */
//#define REDIS_ADDR ((unsigned long int)0xC0A8A00C) //192.168.160.12	/* TJ org */
#define REDIS_ADDR ((unsigned long int)0xc0a85d83) //10.0.2.6			/* 31 May TJChoi : could be replaced by argv[]  */
#define REDIS_PORT 6379

/* Host ID, unique identifier for each host */
#define HOST_ID 12345

/*
 * DEBUGGING
 */
/* Output syscall info in human-reable format to kernel debug log */
//#define LOG_TO_KERNEL_BUF
//#define LIMITED_TESTING_ONLY

