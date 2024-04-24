#ifndef BASIC_H
#define BASIC_H

#include "syshead.h"    

/* size of an array */
#define SIZE(x) (sizeof(x)/sizeof(x[0]))

/* clear an object */
#define CLEAR(x) memset(&(x), 0, sizeof(x))

/* safe free */
#define safe_free(pptr) do { \
	__typeof__((pptr)) volatile _pptr = (pptr); \
	if(!_pptr) { \
		break; \
	} \
	free(_pptr); \
	_pptr = NULL; \
} while(0)

#endif
