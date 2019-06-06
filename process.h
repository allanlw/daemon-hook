#ifndef _PROCESS_H
#define _PROCESS_H

#include <stdio.h>

void wait_for_all_children_to_die(void) __attribute__ ((noreturn));
void die_error(void) __attribute__ ((noreturn));

extern int debug_level;
extern int use_colors;

#define COLOR(x) (use_colors ? fputs(x, stderr) : 0)

#define RED COLOR("\x1b[31m")
#define YELLOW COLOR("\x1b[33m")
#define BLUE COLOR("\x1b[34m")
#define RESET COLOR("\x1b[39m")

#define die_printf(...) do { \
    RED; \
    fprintf(stderr, __VA_ARGS__); \
    RESET; \
    fflush(stderr); \
    die_error(); \
} while (0)

#define die_perror(s) do { \
    RED; \
    perror(s); \
    RESET; \
    fflush(stderr); \
    die_error(); \
} while (0)

#define warn_printf(...) do { \
    if (debug_level >= 0) { \
      YELLOW; \
      fprintf(stderr, __VA_ARGS__); \
      RESET; \
      fflush(stderr); \
    } \
} while (0)

#define info_printf(...) do { \
    if (debug_level >= 1) { \
      BLUE; \
      fprintf(stderr, __VA_ARGS__); \
      RESET; \
      fflush(stderr); \
    } \
} while (0)

#endif
