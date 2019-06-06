#include "tidi.h"

#include <time.h>

#include "concurrency.h"

static struct timespec global_time;
static eventfd_semaphore time_lock;

void daemon_hook_init_tidi(void) {
  clock_gettime(CLOCK_REALTIME, &global_time);

  eventfd_semaphore_init(&time_lock, 1);
}

static void timespec_normalize(struct timespec *s) {
  const long nanosec_per_sec = 1000000000;

  while (s->tv_nsec > nanosec_per_sec) {
    s->tv_nsec -= nanosec_per_sec;
    s->tv_sec += 1;
  }
  while (s->tv_nsec < 0) {
    s->tv_nsec += nanosec_per_sec;
    s->tv_sec -= 1;
  }

}

void daemon_hook_advance_clock(time_t sec, long nsec) {
  eventfd_semaphore_acquire(&time_lock);
  global_time.tv_sec += sec;
  global_time.tv_nsec += nsec;

  timespec_normalize(&global_time);
  eventfd_semaphore_release(&time_lock);
}
