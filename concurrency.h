#ifndef _CONCURRENCY_H
#define _CONCURRENCY_H

typedef struct eventfd_semaphore_s {
  int eventfd;
} eventfd_semaphore;

int eventfd_semaphore_init(eventfd_semaphore *, unsigned int count);
int eventfd_semaphore_acquire(eventfd_semaphore *);
int eventfd_semaphore_release(eventfd_semaphore *);

typedef struct eventfd_condition_s {
  eventfd_semaphore* wrapped_lock;
  eventfd_semaphore semaphore;

  eventfd_semaphore waiters_lock;
  int waiters;

  eventfd_semaphore handshake;
} eventfd_condition;

int eventfd_condition_init(eventfd_condition *, eventfd_semaphore *m);
int eventfd_condition_wait(eventfd_condition *);
int eventfd_condition_signal(eventfd_condition *);
int eventfd_condition_broadcast(eventfd_condition *);

int eventfd_condition_prewait(eventfd_condition *);
int eventfd_condition_fd(eventfd_condition *);
int eventfd_condition_ackwait(eventfd_condition *);
int eventfd_condition_cancelwait(eventfd_condition *);

#endif
