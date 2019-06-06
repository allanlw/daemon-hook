#ifndef _TIDI_H
#define _TIDI_H

#include <sys/types.h>

void daemon_hook_init_tidi(void);
void daemon_hook_advance_clock(time_t sec, long nsec);

#endif
