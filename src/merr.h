#ifndef MERR_H
#define MERR_H

#include <stdio.h>	/* stderr */
#include <stdarg.h>	/* va_list, ... */
#include <stdio.h>	/* fputs */
#include <stdlib.h>	/* exit */
#include <pthread.h>	/* pthread_mutex_lock() */
#include <sys/time.h>	/* gettimeofday() */

enum merr_suppress {
  s_none = 0,
  s_info,
  s_warning,
  s_error,
};

void merr_suppress(int);
void die_set_cb(void (*)());
void fprintfp(FILE *, const char *, ...);
void die(int, const char *, ...);
void error(const char *, ...);
void warning(const char *, ...);
void info(const char *, ...);
void dbg(const char *, ...);

#endif /* MERR_H */
