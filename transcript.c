#include "transcript.h"

#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>

#include "concurrency.h"
#include "process.h"
#include "config.h"
#include "tidi.h"

/*

The transcript format is block based, with blocks of TRANSCRIPT_BLOCK_SIZE bytes.
If the length of the transcript is not a multiple of the block size, any trailing bytes are ignored.

Each block consists of a data portion and a control byte.
The control byte is the final byte of the block.
The block's data portion is the first TRANSCRIPT_BLOCK_SIZE bytes of the block,
with repeated instances of the control byte stripped from the end.

The control byte contains the following data fields:

bits 0-1: indicate the stream onto which this message arrives.
  stream numbers that have not been seen imply an accept call.
bits 2-4: indicate the wait time between packet arrivals

possible future use cases for the extra bits:
  - "continue" bit, to allow for transmission of packets larger than the block size.
  - "target" field - to indicate which listening socket to send to.
  - "close" bit - to allow stream id re-use.

*/
static uint8_t *transcript = NULL;

struct transcript_state_s {
  size_t length;
  volatile size_t current_location;
  volatile int stream_is_initialized[5];
  volatile int stream_refcnt[5];
  eventfd_semaphore lock;
  eventfd_condition cond;
};

static struct transcript_state_s *transcript_state = NULL;

static void transcript_state_changed(void);

static void daemon_hook_load_transcript(void) {
  char *transcript_path = getenv("DAEMON_HOOK_TRANSCRIPT");
  if (transcript_path == NULL) {
    die_printf("DAEMON_HOOK_TRANSCRIPT is not set!\n");
  }

  int fd = open(transcript_path, O_RDONLY);
  if (fd < 0) {
    die_perror("Failed to open DAEMON_HOOK_TRANSCRIPT");
  }

  struct stat tstat;

  if (fstat(fd, &tstat) < 0) {
    die_perror("Failed to stat DAEMON_HOOK_TRANSCRIPT");
  }

  transcript = mmap(NULL, tstat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

  if (transcript == NULL) {
    die_perror("Failed to mmap transcript");
  }

  transcript_state->length = tstat.st_size;

  close(fd);
}

static int current_control_byte(void) {
  if (transcript_state->length - (transcript_state->current_location & TRANSCRIPT_TOP_MASK) < TRANSCRIPT_BLOCK_SIZE) {
    return -1;
  }
  return transcript[(transcript_state->current_location & TRANSCRIPT_TOP_MASK) + TRANSCRIPT_BLOCK_SIZE - 1];
}

static int current_wait_amount(void) {
  int cur = current_control_byte();

  if (cur < 0) {
    return cur;
  } else {
    return (cur >> 2) & 0x7;
  }
}

int transcript_next_stream(void) {
  int cur = current_control_byte();
  if (cur < 0) { return cur; }
  // use one indexed streams
  else { return (cur & 0x03) + 1; }
}

action_e transcript_next_action(void) {
  int cur = transcript_next_stream();
  if (cur < 0) {
    info_printf("DONE@%lu\n", transcript_state->current_location >> TRANSCRIPT_BITS);
    return E_DONE;
  } else {
    if (transcript_state->stream_is_initialized[cur]) {
      info_printf("PACKET(%d)@%lu\n", cur, transcript_state->current_location >> TRANSCRIPT_BITS);
      return E_PACKET;
    } else {
      info_printf("ACCEPT(%d)@%lu\n", cur, transcript_state->current_location >> TRANSCRIPT_BITS);
      return E_ACCEPT;
    }
    return transcript_state->stream_is_initialized[cur] ? E_PACKET : E_ACCEPT;
  }
}

size_t transcript_packet_length(void) {
  int len = TRANSCRIPT_BLOCK_SIZE - 1;
  int ctrl = current_control_byte();
  while (transcript[(transcript_state->current_location & TRANSCRIPT_TOP_MASK) + len - 1] == ctrl && len > 1) {
    len--;
  }
  return len;
}

size_t transcript_packet_length_left(void) {
  // subtract however far we've already read in the current packet
  return transcript_packet_length() - (transcript_state->current_location & TRANSCRIPT_REMAINDER_MASK);
}

uint8_t *transcript_packet_data(void) {
  return &transcript[transcript_state->current_location];
}

void transcript_advance(size_t amount) {
  size_t left = transcript_packet_length_left();
  if (amount > left) {
    die_printf("Cannot advance by an amount greater than what is left in the packet!\n");
  } else if (amount == left) {
    transcript_state->current_location = (transcript_state->current_location & TRANSCRIPT_TOP_MASK) + TRANSCRIPT_BLOCK_SIZE;

    long x = current_wait_amount();
    daemon_hook_advance_clock(0, TRANSCRIPT_TIME_DELAY(x));

    transcript_state_changed();
  } else {
    transcript_state->current_location += amount;
  }
}

int transcript_accept_stream(void) {
  int cur = transcript_next_stream();
  transcript_state->stream_is_initialized[cur] = 1;
  transcript_state->stream_refcnt[cur] = 1;
  transcript_state_changed();

  return cur;
}

void transcript_close_stream(int stream) {
  transcript_state->stream_refcnt[stream] -= 1;
  if (transcript_state->stream_refcnt[stream] == 0) {
    transcript_state->stream_is_initialized[stream] = 0;
    // technically this could change the state.
    transcript_state_changed();
  }
}

void transcript_ref_stream(int stream) {
  transcript_state->stream_refcnt[stream] += 1;
}

static void daemon_hook_init_transcript_semaphore(void) {
  if (eventfd_semaphore_init(&transcript_state->lock, 1) < 0 ||
      eventfd_condition_init(&transcript_state->cond, &transcript_state->lock) < 0) {
    die_perror("Failed to initialize eventfd structures!");
  }
}

// Precondition: Currently holding the lock.
// This is similar to pthread_cond_broadcast
static void transcript_state_changed(void) {
  eventfd_condition_broadcast(&transcript_state->cond);
}

// Precondition: not currently holding the lock
// This corresponds to pthread_mutex_unlock
void transcript_lock(void) {
  eventfd_semaphore_acquire(&transcript_state->lock);
}

// Precondition: currently holding the lock
// This corresponds to pthread_mutex_lock
void transcript_unlock(void) {
  eventfd_semaphore_release(&transcript_state->lock);
}

// Precondition: currently holding the lock
// Postcondition: currently holding the lock, and the state is different
// similar to pthread_cond_wait
void transcript_wait_for_transition(void) {
  eventfd_condition_wait(&transcript_state->cond);
}

eventfd_condition* transcript_get_transition_condition(void) {
  return &transcript_state->cond;
}

void daemon_hook_init_transcript(void) {
  transcript_state = mmap(NULL, sizeof(struct transcript_state_s), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

  if (transcript_state == 0) {
    die_perror("Could not mmap shared transcript state!");
  }

  daemon_hook_init_transcript_semaphore();
  daemon_hook_load_transcript();
}
