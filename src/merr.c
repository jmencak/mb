#include "merr.h"

pthread_mutex_t stderr_lock = PTHREAD_MUTEX_INITIALIZER;
static void (*die_cb)() = NULL;

void fprintfp(FILE *fd, const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);

  pthread_mutex_lock(&stderr_lock);
  vfprintf(fd, fmt, ap);
  pthread_mutex_unlock(&stderr_lock);

  va_end(ap);
}

void die(int err, const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);

  pthread_mutex_lock(&stderr_lock);
  fputs("die: ", stderr);
  vfprintf(stderr, fmt, ap);
  pthread_mutex_unlock(&stderr_lock);
  if (die_cb) die_cb();

  va_end(ap);
  exit(err);
}

void die_set_cb(void (*cb)(int)) {
  die_cb = cb;
}

void error(const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);

  pthread_mutex_lock(&stderr_lock);
  fputs("error: ", stderr);
  vfprintf(stderr, fmt, ap);
  pthread_mutex_unlock(&stderr_lock);

  va_end(ap);
}

void warning(const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);

  pthread_mutex_lock(&stderr_lock);
  fputs("warning: ", stderr);
  vfprintf(stderr, fmt, ap);
  pthread_mutex_unlock(&stderr_lock);

  va_end(ap);
}

void info(const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);

  pthread_mutex_lock(&stderr_lock);
  fputs("info: ", stderr);
  vfprintf(stderr, fmt, ap);
  pthread_mutex_unlock(&stderr_lock);

  va_end(ap);
}
