#include "concurrency.h"

#include <sys/eventfd.h>
#include <unistd.h>

// TODO: none of the functions in this file check errors properly

// Semaphore var impl

int eventfd_semaphore_init(eventfd_semaphore *s, unsigned int count) {
  return (s->eventfd = eventfd(count, EFD_SEMAPHORE));
}

int eventfd_semaphore_acquire(eventfd_semaphore *s) {
  uint64_t v = 0;
  return read(s->eventfd, &v, sizeof(v));
}

int eventfd_semaphore_release(eventfd_semaphore *s) {
  uint64_t v = 1;
  return write(s->eventfd, &v, sizeof(v));
}

// Condition var impl
// Algorithm for this is from https://www.microsoft.com/en-us/research/publication/implementing-condition-variables-with-semaphores/

int eventfd_condition_init(eventfd_condition *c, eventfd_semaphore *m) {
  c->wrapped_lock = m;
  c->waiters = 0;
  if (eventfd_semaphore_init(&c->semaphore, 0) < 0 ||
      eventfd_semaphore_init(&c->waiters_lock, 1) < 0 ||
      eventfd_semaphore_init(&c->handshake, 0) < 0) {
    return -1;
  }

  return 0;
}

// Pre-condition: this thread holds the lock m
int eventfd_condition_wait(eventfd_condition *c) {
  eventfd_semaphore_acquire(&c->waiters_lock);
  c->waiters += 1;
  eventfd_semaphore_release(&c->waiters_lock);

  eventfd_semaphore_release(c->wrapped_lock);

  // This is where the thread does the primary waiting.

  eventfd_semaphore_acquire(&c->semaphore);
  eventfd_semaphore_release(&c->handshake);
  eventfd_semaphore_acquire(c->wrapped_lock);

  return 0;
}

// Pre-condition: this thread holds the lock m
// Essentially these three functions are eventfd_condition_wait
// but split into three separate functions
int eventfd_condition_prewait(eventfd_condition *c) {
  eventfd_semaphore_acquire(&c->waiters_lock);
  c->waiters++;
  eventfd_semaphore_release(&c->waiters_lock);

  eventfd_semaphore_release(c->wrapped_lock);
  return 0;
}
// When this is readable, we're done waiting.
int eventfd_condition_fd(eventfd_condition *c) {
  return c->semaphore.eventfd;
}
// The thread got tolde from poll/select/epoll that it was ready to read
int eventfd_condition_ackwait(eventfd_condition *c) {
  eventfd_semaphore_acquire(&c->semaphore);
  eventfd_semaphore_release(&c->handshake);
  eventfd_semaphore_acquire(c->wrapped_lock);
  return 0;
}
// this function gets called if we decide to bail from waiting for the condition
// essentially we have to "undo" that we requested to wait.
// this, like, super sucks. especially if someone has already decided to broadcast
// and is waiting for us to ack them.
int eventfd_condition_cancelwait(eventfd_condition *c) {
  // TODO: there is a potential deadlock here I'm not sure how to fix.
  // the deadlock occurs when someone tries to signal() or brodcast() to this thread
  // but we decided to cancel. I'm... not really sure how to fix this.
  eventfd_semaphore_acquire(&c->waiters_lock);
  c->waiters--;
  eventfd_semaphore_release(&c->waiters_lock);

  // should this be first...?
  eventfd_semaphore_acquire(c->wrapped_lock);
  return 0;
}

int eventfd_condition_signal(eventfd_condition *c) {
  eventfd_semaphore_acquire(&c->waiters_lock);
  if (c->waiters > 0) {
    c->waiters--;
    eventfd_semaphore_release(&c->semaphore);
    eventfd_semaphore_acquire(&c->handshake);
  }
  eventfd_semaphore_release(&c->waiters_lock);

  return 0;
}

int eventfd_condition_broadcast(eventfd_condition *c) {
  eventfd_semaphore_acquire(&c->waiters_lock);

  for (int i = 0; i < c->waiters; i++) {
    eventfd_semaphore_release(&c->semaphore);
  }
  while (c->waiters > 0) {
    c->waiters--;
    eventfd_semaphore_acquire(&c->handshake);
  }

  eventfd_semaphore_release(&c->waiters_lock);

  return 0;
}
