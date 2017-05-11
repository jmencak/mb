#ifndef STATS_H
#define STATS_H

#include <stdio.h>	/* FILE, stdout, stderr, fopen(), fclose() */
#include "net.h"	/* connection struct */

#define MAX(x, y) ((x) > (y)? (x) : (y))
#define MIN(x, y) ((x) < (y)? (x) : (y))

/* Module functions */
extern int write_stats_line(FILE *, connection *, char *);

#endif /* STATS_H */
