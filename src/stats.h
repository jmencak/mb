#ifndef STATS_H
#define STATS_H

#include <stdio.h>	/* FILE, stdout, stderr, fopen(), fclose() */
#include "net.h"	/* connection struct */

#ifndef MAX
#define MAX(x, y) ((x) > (y)? (x) : (y))
#endif
#ifndef MIN
#define MIN(x, y) ((x) < (y)? (x) : (y))
#endif

/* Module functions */
extern int write_stats_line(FILE *, connection *, char *);

#endif /* STATS_H */
