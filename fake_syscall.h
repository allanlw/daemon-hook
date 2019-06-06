#ifndef _FAKE_SYSCALL_H
#define _FAKE_SYSCALL_H

#include <stdint.h>

#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <poll.h>
#include <sched.h>

#include "config.h"

extern int min_dummy_fd;


// These are our "passthrough" structures
// This table is given an exception in the hooking code, to passthrough to the real poll implementation
extern struct pollfd passthrough_poll_fds[MAX_POLL_FDS];

// Passthrough for select()
extern fd_set passthrough_read_fdset;

// Passthrough arguments for nanosleep
extern struct timespec passthrough_req_timespec;
extern struct timespec passthrough_rem_timespec;

int daemon_hook_fake_socket(int domain, int type, int protocol);
int daemon_hook_fake_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
int daemon_hook_fake_getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
int daemon_hook_fake_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int daemon_hook_fake_listen(int sockfd, int backlog);
int daemon_hook_fake_accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
int daemon_hook_fake_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int daemon_hook_fake_getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
ssize_t daemon_hook_fake_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
ssize_t daemon_hook_fake_send(int sockfd, void *buf, size_t len, int flags);
ssize_t daemon_hook_fake_sendto(int sockfd, void *buf, size_t len, int flags, struct sockaddr *dest_addr, socklen_t *addrlen);
int daemon_hook_fake_close(int fd);
int daemon_hook_fake_shutdown(int sockfd, int how);

int daemon_hook_fake_poll(struct pollfd *fds, nfds_t nfds, int timeout);

int daemon_hook_fake_select(int nfds, fd_set *readfds, fd_set *writefds,
                  fd_set *exceptfds, struct timeval *timeout);

int daemon_hook_fake_fcntl(int fd, int cmd, uint64_t arg);
int daemon_hook_fake_ioctl(int fd, int cmd, uint64_t arg);

int daemon_hook_fake_nanosleep(const struct timespec *req, struct timespec *rem);

// This isn't actually a fake syscall, it's run before clone()
void daemon_hook_preclone(void);
#endif
