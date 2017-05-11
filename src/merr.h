#ifndef MERR_H
#define MERR_H

#include <stdio.h>	/* stderr */
#include <stdarg.h>	/* va_list, ... */
#include <stdio.h>	/* fputs */
#include <stdlib.h>	/* exit */
#include <pthread.h>	/* pthread_mutex_lock() */

void fprintfp(FILE *, const char *, ...);
void die(int, const char *, ...);
void die_set_cb(void (*)());
void error(const char *, ...);
void warning(const char *, ...);
void info(const char *, ...);

#endif /* MERR_H */
