#include "fake_syscall.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <seccomp.h>
#include <sys/syscall.h>
#include <asm/ioctls.h>

#include "transcript.h"
#include "concurrency.h"
#include "process.h"

typedef struct {
  unsigned int is_active : 1; // an "Active" socket is managed by the hook
  unsigned int is_nonblock : 1;
  unsigned int is_bound : 1;
  unsigned int is_listen : 1;
  unsigned int is_writable : 1;
  unsigned int is_readable : 1;
  int domain;
  int type;
  int protocol;
  int transcript_channel;
} fake_socket_info;

static fake_socket_info sockets[NUM_DUMMY_FDS];

int min_dummy_fd;

#define SOCK_INFO(fd) (sockets[(fd) - min_dummy_fd])

static pthread_mutex_t used_dummy_fds_mutex = PTHREAD_MUTEX_INITIALIZER;
static int used_dummy_fds = 0;

static void write_fakeaddr(int id, struct sockaddr *addr, socklen_t addrlen, int domain) {
  memset(addr, 'A' + id, addrlen);
  addr->sa_family = domain;
}

static int get_unused_dummy_fd(void) {
  pthread_mutex_lock(&used_dummy_fds_mutex);
  int res = min_dummy_fd + used_dummy_fds;
  used_dummy_fds++;
  if (used_dummy_fds > NUM_DUMMY_FDS) {
    die_printf("Failed to allocate a dummy fd! Increase NUM_DUMMY_FDS\n");
  }
  pthread_mutex_unlock(&used_dummy_fds_mutex);
  memset(&SOCK_INFO(res), 0, sizeof(fake_socket_info));
  SOCK_INFO(res).is_active = 1;
  return res;
}

static void describe_sock(int fd) {
  info_printf("socket call on fd=%d(%s%s%s%s%s) domain=%d, type=%d, proto=%d\n", fd,
        SOCK_INFO(fd).is_nonblock?"nonblock ":"", SOCK_INFO(fd).is_bound ? "bound " : "",
        SOCK_INFO(fd).is_listen?"listen ":"", SOCK_INFO(fd).is_readable ? "read " : "",
        SOCK_INFO(fd).is_writable?"write ":"", SOCK_INFO(fd).domain, SOCK_INFO(fd).type, SOCK_INFO(fd).protocol);
}

// shared processing for socket fd param checking
#define check_fd_sock(fd) \
  do { \
    if (fd < min_dummy_fd || fd >= min_dummy_fd + NUM_DUMMY_FDS || !SOCK_INFO(fd).is_active) { \
      return -ENOTSOCK; \
    } else if ((fd) < 0) { \
      return -EBADF; \
    } \
    describe_sock(fd); \
  } while (0)

// This is our (very restricted) implementation of socket()
// Return errors for anything that isn't supported.
// Allocate a fake fd, to use up the fd space, but effectively it can't be used for anything
int daemon_hook_fake_socket(int domain, int type, int protocol) {
  if (type & SOCK_CLOEXEC) {
    warn_printf("Trapped socket() call asked for cloexec, ignoring...\n");
    type &= ~SOCK_CLOEXEC;
  }

  int is_nonblock = !!(type & SOCK_NONBLOCK);

  type &= ~SOCK_NONBLOCK;

  if (domain != AF_INET && domain != AF_INET6) {
    die_printf("Trapped socket() call for unsupported domain(%d), only AF_INET6? is supported\n", domain);
  }

  if (type != SOCK_STREAM && type != SOCK_DGRAM) {
    die_printf("Trapped socket() call for unsupported type(%d), only SOCK_STREAM(%d) is supported\n", type, SOCK_STREAM);
  }

  if (protocol != 0 && protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) {
    die_printf("Trapped socket() call had unsupported protocol(%d).\n", protocol);
  }

  int res = get_unused_dummy_fd();

  fake_socket_info* info = &SOCK_INFO(res);

  info->domain = domain;
  info->protocol = protocol;
  info->type = type;
  info->is_nonblock = is_nonblock;

  return res;
}

int daemon_hook_fake_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) {
  check_fd_sock(sockfd);

  // SOL_SOCKET = 1

  // we really don't care about these options, just pretend to support them
  if ((level == SOL_SOCKET && (optname == SO_REUSEADDR || optname == SO_LINGER || optname == SO_KEEPALIVE || optname == SO_BROADCAST)) ||
      (level == SOL_TCP && (optname == TCP_NODELAY || optname == TCP_KEEPCNT || optname == TCP_KEEPIDLE || optname == TCP_KEEPINTVL))) {
    return 0;
  }

  warn_printf("Unimplemented setsockopt call (level=%d, optname=%d)\n", level, optname);
  return -ENOPROTOOPT;
}

int daemon_hook_fake_getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen) {
  check_fd_sock(sockfd);

  if (level == SOL_SOCKET && optname == SO_TYPE) {
    if (optval) {
      memmove(optval, &SOCK_INFO(sockfd).type, sizeof(SOCK_INFO(sockfd).type) > *optlen ? *optlen : sizeof(SOCK_INFO(sockfd).type));
    }
    return 0;
  // Added for mongodb
  } else if (level == SOL_TCP && optname == TCP_KEEPIDLE) {
    if (optval) {
      int res = 7200;
      memmove(optval, &res, sizeof(int) > *optlen ? *optlen : sizeof(int));
    }
    return 0;
  // Added for mongodb
  } else if (level == SOL_TCP && optname == TCP_KEEPINTVL) {
    if (optval) {
      int res = 75;
      memmove(optval, &res, sizeof(int) > *optlen ? *optlen : sizeof(int));
    }
    return 0;
  }

  warn_printf("Unimplemented getsockopt call (level=%d, optname=%d)\n", level, optname);
  return -ENOPROTOOPT;
}

int daemon_hook_fake_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  check_fd_sock(sockfd);
  if (SOCK_INFO(sockfd).is_bound) {
    return -EINVAL;
  }
  SOCK_INFO(sockfd).is_bound = 1;

  if (SOCK_INFO(sockfd).type == SOCK_DGRAM) {
    SOCK_INFO(sockfd).is_writable = 1;
    SOCK_INFO(sockfd).is_readable = 1;
  }

  return 0;
}

int daemon_hook_fake_listen(int sockfd, int backlog) {
  check_fd_sock(sockfd);

  SOCK_INFO(sockfd).is_listen = 1;

  return 0;
}

int daemon_hook_fake_accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
  check_fd_sock(sockfd);

  if (!SOCK_INFO(sockfd).is_listen || !SOCK_INFO(sockfd).is_bound) {
    return -EINVAL;
  }

  if (flags & SOCK_CLOEXEC) {
    warn_printf("Trapped accept[4]() call asked for cloexec, ignoring...\n");
    flags &= ~SOCK_CLOEXEC;
  }

  transcript_lock();

try_accept:
  switch (transcript_next_action()) {
  case E_ACCEPT:
    break;
  case E_PACKET:
    if (SOCK_INFO(sockfd).is_nonblock) {
      return -EAGAIN;
    }
    transcript_wait_for_transition();
    goto try_accept;
  case E_DONE:
    // TODO: Something reasonable here...?
    transcript_unlock();
    warn_printf("Done on accept4.\n");
    wait_for_all_children_to_die();
  default:
    die_printf("Unknown transcript action type in accept4\n");
  }

  // Allocate a "fake" file descriptor that effectively can't be used for anything
  int res = get_unused_dummy_fd();
  fake_socket_info* info = &SOCK_INFO(res);

  info->domain = SOCK_INFO(sockfd).domain;
  info->protocol = SOCK_INFO(sockfd).protocol;
  info->type =SOCK_INFO(sockfd).type;
  info->is_nonblock = !!(flags & SOCK_NONBLOCK);
  info->is_writable = 1;
  info->is_readable = 1;
  info->transcript_channel = transcript_accept_stream();

  // give it a fake address...
  // this is, like, really really terrible code.
  // also, we don't check a lot of the things that should be checked, etc.
  // big TODO here, I guess
  if (addr != NULL && *addrlen > sizeof(addr->sa_family)) {
    write_fakeaddr(info->transcript_channel, addr, *addrlen, info->domain);
  }

  transcript_unlock();

  return res;
}

int daemon_hook_fake_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  check_fd_sock(sockfd);

  if (addr == NULL || addrlen == NULL) {
    return -EFAULT;
  } else if (*addrlen < sizeof(addr->sa_family)) {
    return -EINVAL;
  }

  write_fakeaddr(8 + (sockfd - min_dummy_fd), addr, *addrlen, SOCK_INFO(sockfd).domain);

  return 0;
}

int daemon_hook_fake_getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  check_fd_sock(sockfd);

  if (addr == NULL || addrlen == NULL) {
    return -EFAULT;
  } else if (*addrlen < sizeof(addr->sa_family)) {
    return -EINVAL;
  } else if (!SOCK_INFO(sockfd).transcript_channel) {
    return -ENOTCONN;
  }

  memset(addr, 'A' + SOCK_INFO(sockfd).transcript_channel, *addrlen);
  addr->sa_family = SOCK_INFO(sockfd).domain;

  return 0;
}

int daemon_hook_fake_close(int fd) {
  check_fd_sock(fd);
  if (!SOCK_INFO(fd).is_active) {
    return -EBADF;
  }
  SOCK_INFO(fd).is_active = 0;
  if (SOCK_INFO(fd).transcript_channel) {
    transcript_lock();
    transcript_close_stream(SOCK_INFO(fd).transcript_channel);
    transcript_unlock();
  }
  return 0;
}

struct pollfd passthrough_poll_fds[MAX_POLL_FDS];

int daemon_hook_fake_poll(struct pollfd *fds, nfds_t nfds, int timeout) {
  if (timeout != 0) {
    die_printf("poll hasn't implemented fake time\n");
  }

  nfds_t num_fake_fds = 0, num_real_fds = 0;

  for (size_t i = 0; i < nfds; i++) {
    int fd = fds[i].fd;
    if (fd < min_dummy_fd || fd >= min_dummy_fd + NUM_DUMMY_FDS) {
      num_real_fds += 1;
    } else {
      num_fake_fds += 1;
    }
  }

  if (num_real_fds == nfds) {
    if (nfds > MAX_POLL_FDS) {
      die_printf("MAX_POLL_FDS(%d) is less than requested poll size of %d. Need to increase.\n", MAX_POLL_FDS, (int)nfds);
    }

    // passthrough_poll_fds has been hooked as an exemption that doesn't trap
    // to our fake poll handler
    memmove(passthrough_poll_fds, fds, nfds * sizeof(struct pollfd));
    int res = poll(passthrough_poll_fds, nfds, timeout);
    memmove(fds, passthrough_poll_fds, nfds * sizeof(struct pollfd));
    return res;
  } else if (num_fake_fds != nfds) {
    die_printf("Unhandled mixed poll with %d fds\n", (int)nfds);
  }

  nfds_t unused = 0;
  transcript_lock();
  for (nfds_t i = 0; i < nfds; i++) {
    int fd = fds[i].fd;
    fds[i].revents = 0;
    if (!SOCK_INFO(fd).is_active) {
      fds[i].revents |= POLLERR;
      continue;
    }
    if (transcript_next_action() == E_DONE) {
      if (fds[i].events & POLLIN) {
        fds[i].revents |= POLLIN;
      }
      continue;
    }
    // Ready to read on fake listening sockets for accept
    // Ready to read on fake stream sockets if their channel matches
    if ((fds[i].events & (POLLIN | POLLPRI)) && (
          (transcript_next_action() == E_ACCEPT && (SOCK_INFO(fd).is_listen || SOCK_INFO(fd).type == SOCK_DGRAM)) ||
          (transcript_next_action() == E_PACKET && SOCK_INFO(fd).transcript_channel == transcript_next_stream()))) {
      fds[i].revents |= POLLIN;
    }

    // Always be ready for writing on fake sockets.
    // TODO check for is_writable and do whatever is correct here
    if (fds[i].revents & POLLOUT) {
      fds[i].revents |= POLLOUT;
    }

    if (fds[i].revents == 0) {
      unused += 1;
    }
  }
  transcript_unlock();
  if (unused != nfds) {
    return nfds - unused;
  }
  if (timeout == 0) {
    return 0;
  }

  // TODO: we have a timeout, which maybe we should block on
  // For now, just pretend we waited
  // See also: select
  return 0;
}

int daemon_hook_fake_fcntl(int fd, int cmd, uint64_t arg) {
  check_fd_sock(fd);

  if (cmd == F_GETFL) {
    // TODO: Properly handle socket modes... really they should  handle shutdowns...
    return O_RDWR | (SOCK_INFO(fd).is_nonblock?O_NONBLOCK:0);
  } else if (cmd == F_SETFL) {
    if (arg & O_NONBLOCK) {
      SOCK_INFO(fd).is_nonblock = 1;
    } else {
      SOCK_INFO(fd).is_nonblock = 0;
    }
    arg &= ~O_NONBLOCK;
    if (arg & (O_ASYNC | O_DIRECT | O_NOATIME | O_APPEND)) {
      die_printf("Unhandled socket F_SETFL on fd(%d), arg=%lx\n", fd, arg);
    }
    return 0;
  } else if (cmd == F_GETFD) {
    return 0;
  } else if (cmd == F_SETFD) {
    if (arg & O_CLOEXEC) {
      warn_printf("Ignorning O_CLOEXEC....");
    }
    return 0;
  }
  die_printf("Unhandled socket fcntl on fd(%d), cmd=0x%x, arg=0x%lx\n", fd, cmd, arg);
}

int daemon_hook_fake_ioctl(int fd, int cmd, uint64_t arg) {
  check_fd_sock(fd);

  if (cmd == FIONBIO) {
    // This apparently works in linux, so lets honor it.
    SOCK_INFO(fd).is_nonblock = 1;
    return 0;
  }

  die_printf("Unhandled socket ioctl on fd(%d), cmd=0x%x, arg=0x%lx\n", fd, cmd, arg);
}

ssize_t daemon_hook_fake_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
  check_fd_sock(sockfd);

  if (!buf) {
    return -EINVAL;
  }

  if (src_addr && !addrlen) {
    return -EINVAL;
  }

  if (SOCK_INFO(sockfd).transcript_channel == 0 && SOCK_INFO(sockfd).type == SOCK_STREAM) {
    return -ENOTCONN;
  }

  if (!SOCK_INFO(sockfd).is_readable) {
    die_printf("Recv on nonreadable socket...? Something strange is going on.\n");
    return 0;
  }

  int is_nonblocking = SOCK_INFO(sockfd).is_nonblock;

  if (flags & MSG_DONTWAIT) {
    is_nonblocking = 1;
    flags &= ~MSG_DONTWAIT;
  }

  flags &= ~MSG_NOSIGNAL; // harmless in recv

  if (flags != 0) {
    die_printf("Unsupported flags(%x) in recv(%d)\n", flags, sockfd);
  }

  transcript_lock();

try_read:
  if ((SOCK_INFO(sockfd).type == SOCK_DGRAM && transcript_next_action() != E_DONE) ||
      (SOCK_INFO(sockfd).type == SOCK_STREAM && transcript_next_action() == E_PACKET && transcript_next_stream() == SOCK_INFO(sockfd).transcript_channel)) {
    size_t available = transcript_packet_length_left();
    available = len < available ? len : available;
    memmove(buf, transcript_packet_data(), available);

    if (src_addr) {
      write_fakeaddr(transcript_next_stream(), src_addr, *addrlen, SOCK_INFO(sockfd).domain);
    }

    transcript_advance(available);
    transcript_unlock();
    return available;
  }

  if (transcript_next_action() == E_DONE) {
    transcript_unlock();
    warn_printf("Done on recv.\n");
    wait_for_all_children_to_die();
  }

  if (is_nonblocking) {
    transcript_unlock();
    return -EAGAIN;
  }

  transcript_wait_for_transition();
  goto try_read;
}

ssize_t daemon_hook_fake_send(int sockfd, void *buf, size_t len, int flags) {
  check_fd_sock(sockfd);

  if (!buf) {
    return -EINVAL;
  }

  if (!SOCK_INFO(sockfd).is_writable) {
    return -ENOTCONN; // TODO: is this the right error to return...?
  }

  // TODO: support real logging
  if (getenv("DAEMON_HOOK_DEBUG")) {
    write(1, buf, len);
  }

  return len;
}

ssize_t daemon_hook_fake_sendto(int sockfd, void *buf, size_t len, int flags, struct sockaddr *dest_addr, socklen_t *addrlen) {
  check_fd_sock(sockfd);

  warn_printf("Got sendto, pretending it's send()\n");
  return daemon_hook_fake_send(sockfd, buf, len, flags);
}

// doesn't do anything with the fds in the fdset
// that it doesn't know how to deal with
// You MUST BE HOLDING transcript_lock
// note that this does not zero results_read, etc
static int entirely_fake_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, fd_set *results_read, fd_set *results_write, fd_set *results_except) {
  int result_value = 0;

  for (int fd = 0; fd < nfds; fd++) {
    if ((readfds && !FD_ISSET(fd, readfds)) && (writefds && !FD_ISSET(fd, writefds)) && (exceptfds && !FD_ISSET(fd, exceptfds))) {
      continue;
    }

    if (fd < min_dummy_fd || fd >= min_dummy_fd + NUM_DUMMY_FDS || !SOCK_INFO(fd).is_active) {
      continue;
    }

    if (!SOCK_INFO(fd).is_active) {
      return -EBADF;
    }

    // Ready to read on fake listening sockets for accept
    // Ready to read on fake stream sockets if their channel matches
    if ((readfds && FD_ISSET(fd, readfds)) && (
          (transcript_next_action() == E_ACCEPT && (SOCK_INFO(fd).is_listen || SOCK_INFO(fd).type == SOCK_DGRAM)) ||
          (transcript_next_action() == E_PACKET && SOCK_INFO(fd).transcript_channel == transcript_next_stream()) ||
          (transcript_next_action() == E_DONE))) {
      FD_SET(fd, results_read);
      result_value += 1;
    }

    // Always be ready for writing on fake sockets.
    // TODO: check is_writable and return the correct error
    if ((writefds && FD_ISSET(fd, writefds))) {
      FD_SET(fd, results_write);
      result_value += 1;
    }
  }

  return result_value;
}

// This is a passthrough param that doesn't get trapped.
fd_set passthrough_read_fdset;

static int passthrough_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) {
  // I only implemented passthrough logic for the read fdset, not the others. should be easy to add
  if (!readfds) {
    die_printf("Unhandled native select without read fdset\n");
  }

  if (timeout) {
    die_printf("unhooked select with timeout value...\n");
  }

  memmove(&passthrough_read_fdset, readfds, sizeof(passthrough_read_fdset));
  int res = select(nfds, &passthrough_read_fdset, writefds, exceptfds, timeout);
  memmove(readfds, &passthrough_read_fdset, sizeof(passthrough_read_fdset));
  return res;
}

static void copy_nonfake_fds(int nfds, fd_set *in, fd_set *out) {
  if (!in) { return; }
  for (int i = 0; i < nfds; i++) {
    if (i >= min_dummy_fd && i < min_dummy_fd + NUM_DUMMY_FDS) {
      continue;
    }
    if (FD_ISSET(i, in)) {
      FD_SET(i, out);
    }
  }
}

int daemon_hook_fake_select(int nfds, fd_set *readfds, fd_set *writefds,
                  fd_set *exceptfds, struct timeval *timeout) {
  int num_fake_fds = 0, num_real_fds = 0;
  fd_set results_read;
  fd_set results_write;
  fd_set results_except;

  if (nfds < 0) {
    return -EINVAL;
  }

  for (int i = 0; i < nfds; i++) {
    if ((readfds && !FD_ISSET(i, readfds)) && (writefds && !FD_ISSET(i, writefds)) && (exceptfds && !FD_ISSET(i, exceptfds))) {
      continue;
    }

    if (i < min_dummy_fd || i >= min_dummy_fd + NUM_DUMMY_FDS) {
      num_real_fds += 1;
    } else {
      num_fake_fds += 1;
    }
  }

  info_printf("Select with %d fds (real=%d, fake=%d)\n", nfds, num_real_fds, num_fake_fds);

  if (num_fake_fds == 0) {
    return passthrough_select(nfds, readfds, writefds, exceptfds, timeout);
  }
  // try to satisfy with a fake select
  transcript_lock();

try_again:
  FD_ZERO(&results_read);
  FD_ZERO(&results_write);
  FD_ZERO(&results_except);

  int result_value = entirely_fake_select(nfds, readfds, writefds, exceptfds, &results_read, &results_write, &results_except);;

  info_printf("First pass select() returned %d\n", result_value);

  if (result_value < 0) {
    transcript_unlock();
    return result_value; // EBADF or other error
  } else if (result_value > 0) {
    if (readfds) {
      memmove(readfds, &results_read, sizeof(results_read));
    }
    if (writefds) {
      memmove(writefds, &results_write, sizeof(results_write));
    }
    if (exceptfds) {
      memmove(exceptfds, &results_except, sizeof(results_except));
    }
    transcript_unlock();
    return result_value;
  }

  if (num_real_fds == 0) {
    // Non-block check mode.
    if (timeout != NULL && (timeout->tv_sec == 0 && timeout->tv_usec == 0)) {
      transcript_unlock();
      return 0;
    }

    // Block forever mode.
    if (timeout == NULL) {
      transcript_wait_for_transition();
      goto try_again;
    } else {
      // We're in blocking mode, but entirely virtual. No need to actually sleep.
      // TODO: This could expose unrealistic race conditions...? should we sleep just a bit..?
      transcript_unlock();
      return 0;
    }
  } else {
    // This is by far the most complicated part.
    // we need to deal with some real fds and some fake ones.
    // To accomplish this, we'll first checked and see if we can satisfy
    // the select() with only fake results.
    // if we cannot, we construct a new set of parameters to select
    // that contain the realfds and our condition variable's eventfd
    // we then select on those new parameters.
    // in the case that our fake fd was not ready for reading, we roll
    // back the waiting state, and return the results from that real call
    // in the case that our fake fd is ready for reading, we merge
    // the results from the select() call with the results from our new
    // fake fd state.
    fd_set new_reads;
    fd_set new_writes;
    fd_set new_except;

    FD_ZERO(&new_reads);
    FD_ZERO(&new_writes);
    FD_ZERO(&new_except);

try_again_mixed:
    if (readfds)  { copy_nonfake_fds(nfds, readfds, &new_reads); }
    if (writefds) { copy_nonfake_fds(nfds, writefds, &new_writes); }
    if (exceptfds) { copy_nonfake_fds(nfds, exceptfds, &new_except); }

    eventfd_condition *cond = transcript_get_transition_condition();

    int cond_fd = eventfd_condition_fd(cond);
    FD_SET(cond_fd, &new_reads);

    eventfd_condition_prewait(cond);
    result_value = passthrough_select(nfds > cond_fd ? nfds : cond_fd, &new_reads, writefds ? &new_writes : NULL, exceptfds ? &new_except : NULL, timeout);

    // error condition...?
    if (result_value < 0) {
      eventfd_condition_cancelwait(cond);
      transcript_unlock();
      return result_value;
    // we need to incorperate fake results
    } else if (FD_ISSET(cond_fd, &new_reads)) {
      eventfd_condition_ackwait(cond);

      int result_value_fake = entirely_fake_select(nfds, readfds, writefds, exceptfds, &new_reads, &new_writes, &new_except);
      if (result_value_fake < 0) {
        transcript_unlock();
        return result_value_fake;
      } else if (result_value_fake == 0) {
        // Oooofff this sucks. We got woken up by a state transition in the transcript
        // but it didn't satisfy our select.
        goto try_again_mixed;
      }

      transcript_unlock();
      result_value += result_value_fake;

    // there was no fake wakeup to deal with
    } else {
      eventfd_condition_cancelwait(cond);
    }

    transcript_unlock();

    if (readfds) { memmove(readfds, &new_reads, sizeof(fd_set)); }
    if (writefds) { memmove(writefds, &new_writes, sizeof(fd_set)); }
    if (exceptfds) { memmove(exceptfds, &new_except, sizeof(fd_set)); }
    return result_value;
  }
}

int daemon_hook_fake_shutdown(int sockfd, int how) {
  check_fd_sock(sockfd);

  switch(how) {
  case SHUT_RD:
    SOCK_INFO(sockfd).is_readable = 0;
    break;
  case SHUT_WR:
    SOCK_INFO(sockfd).is_writable = 0;
    break;
  case SHUT_RDWR:
    SOCK_INFO(sockfd).is_writable = 0;
    SOCK_INFO(sockfd).is_readable = 0;
    break;
  default:
    return -EINVAL;
  }
  return 0;
}

struct timespec passthrough_req_timespec;
struct timespec passthrough_rem_timespec;

int daemon_hook_fake_nanosleep(const struct timespec *req, struct timespec *rem) {
  memmove(&passthrough_req_timespec, req, sizeof(struct timespec));

  int res = nanosleep(&passthrough_req_timespec, &passthrough_rem_timespec);

  if (rem) {
    memmove(rem, &passthrough_rem_timespec, sizeof(struct timespec));
  }

  return res;
}

// Do something right before clone is called
// BUG: only does fork properly right now...?
void daemon_hook_preclone(void) {
  for (int i = 0; i < NUM_DUMMY_FDS; i++) {
    if (sockets[i].transcript_channel) {
      transcript_ref_stream(sockets[i].transcript_channel);
     }
  }
}
