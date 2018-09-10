#ifndef _PROGGER_UTILS_H
#define _PROGGER_UTILS_H

#include "definitions.h"	/* TJ to seperate codes according to defines.  April, 2018 */

struct log_path {
        char *mem;
        char *name;
};

#ifdef ABSENCE_STRLEN_USER
typedef struct _STR_IN_USERAREA {
	char *user_str;
	unsigned short user_str_len;
} STR_IN_USERAREA;


STR_IN_USERAREA* stUstr_to_kspace(const char __user *u_str);
#endif

#endif
