#ifndef _CONFIG_H
#define _CONFIG_H

// number of 'dummy' fds to allocate at the beginning. This cannot be
// adjusted after enforcing the seccomp rules.
#define NUM_DUMMY_FDS 16

// number of FDs to support for calls to poll().
// a static array is used as a 'passthrough' for the first argument to
// poll (the readfds), and is exempted from the seccomp rules.
// this constant determines the size of that static array.
#define MAX_POLL_FDS 128

// Number of bytes in a block in the transcript.
// note that the maximum number of data bytes is one less than 2**n
// due to the control byte
// needs to be a power of two for masking
#define TRANSCRIPT_BITS 6
#define TRANSCRIPT_BLOCK_SIZE (1 << TRANSCRIPT_BITS)

// masks for the conceptual "block index" and subindex
// when indexing into the transcript file
#define TRANSCRIPT_REMAINDER_MASK (TRANSCRIPT_BLOCK_SIZE - 1)
#define TRANSCRIPT_TOP_MASK (~(TRANSCRIPT_REMAINDER_MASK))

// This is the file descriptor to watch for closing for the afl forkserver
// hooking code. Only needs to be changed if AFL changes theirs.
#define AFL_FORKSRV_FD 198

// This returns the number of nanoseconds to delay for a delay
// of x, which is in the range 0..7
// For now, lets use a simple function which is (x^3)  milliseconds
// These are reasonable network arrival time delays, from 0 to 350ms
// Note that this is before time dilation
#define TRANSCRIPT_TIME_DELAY(x) ((x)*(x)*(x)* 1000000)

#endif
