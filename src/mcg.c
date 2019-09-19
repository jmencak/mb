#include <inttypes.h>		/* UINT64_MAX, uint64_t, ... */
#include <string.h>		/* memcpy() */

#include "mcg.h"

/* 
 * A 128-bit truncated MCG PRNG based on:
 * http://www.pcg-random.org/posts/does-it-beat-the-minimal-standard.html
 */

const __uint128_t MCG64_MULT = ((__uint128_t)UINT64_MAX + 1) * UINT64_C(0x0fc94e3bf4e9ab32) + UINT64_C(0x866458cd56f5e605);

/* The MCG state must be seeded to an odd number. */
void mcg64_seed(__uint128_t *state) {
  *state |= 1;
}

static inline uint64_t mcg64(__uint128_t *state) {
  *state *= MCG64_MULT;

  return *state >> 64;
}

#if 1
/* mcg64cpy() copies "len" number of pseudo-random bytes into output array "out". */
void mcg64cpy(__uint128_t *state, char *out, size_t len) {
  uint64_t rndn;
  size_t n;
  const char *out_end = out + len;

  while (1) {
    rndn = mcg64(state);

    n = (out_end - out) > 8? 8: (out_end - out);
    memcpy(out, &rndn, n);
    out += n;

    if (out >= out_end) {
      return;
    }
  }
}
#else
/* only for testing purposes only */
void mcg64cpy(__uint128_t *state, char *out, size_t len) {
  const char *out_end = out + len;

  for (int i=0;; i++) {
    *out = '0' + i % 10;

    if (++out >= out_end) {
      return;
    }
  }
}
#endif
