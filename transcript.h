#ifndef _TRANSCRIPT_H
#define _TRANSCRIPT_H

#include <stdint.h>
#include <stddef.h>

typedef enum {
  E_ACCEPT,
  E_PACKET,
  E_DONE,
} action_e;

void daemon_hook_init_transcript(void);
int transcript_next_stream(void);
action_e transcript_next_action(void);
int transcript_accept_stream(void);
uint8_t *transcript_packet_data(void);
size_t transcript_packet_length(void);
size_t transcript_packet_length_left(void);
void transcript_advance(size_t amount);
void transcript_close_stream(int stream);
void transcript_ref_stream(int stream);

void transcript_lock(void);
void transcript_unlock(void);
void transcript_wait_for_transition(void);
int transcript_eventfd(void);
struct eventfd_condition_s *transcript_get_transition_condition(void);

#endif
