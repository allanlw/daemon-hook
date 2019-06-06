#include <stdio.h>
#include <seccomp.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <ucontext.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <errno.h>
#include <dlfcn.h>
#include <linux/futex.h>
#include <sys/time.h>

#include "transcript.h"
#include "tidi.h"
#include "fake_syscall.h"
#include "process.h"
#include "config.h"

// Probably could include this properly or something? lol who knows
#ifndef SYS_SECCOMP
#define SYS_SECCOMP 1
#endif

static unsigned long fake_ptid_location;

static int daemon_hook_udp = 0;
static int daemon_hook_inited = 0;

volatile int die_die_die = 0;

sigset_t passthrough_sigset;

static int daemon_hook_fake_sigaction(int signal, const struct sigaction *act, struct sigaction *oldact) {
  warn_printf("Attempt by wrapped process to override SIGSYS. Ignoring, but could cause bad results...\n");
  return -EINVAL;
}

static int daemon_hook_fake_sigprocmask(int how, const sigset_t *set, sigset_t *oldset) {
  memmove(&passthrough_sigset, set, sizeof(sigset_t));
  if (how == SIG_SETMASK || how == SIG_BLOCK) {
    if (sigismember(&passthrough_sigset, SIGSYS)) {
      sigdelset(&passthrough_sigset, SIGSYS);
      warn_printf("Attempt by wrapped process to block SIGSYS. Ignoring...\n");
    }
  }
  return syscall(SYS_rt_sigaction, how, passthrough_sigset, oldset);
}

static int dispatch_syscall(int syscall, uint64_t *args) {
  daemon_hook_advance_clock(0, 1000000); // 1 millisecond

  switch(syscall) {
  case SCMP_SYS(socket):
    return daemon_hook_fake_socket((int)args[0], (int)args[1], (int)args[2]);
  case SCMP_SYS(setsockopt):
    return daemon_hook_fake_setsockopt((int)args[0], (int)args[1], (int)args[2], (void *)args[3], (socklen_t)args[4]);
  case SCMP_SYS(getsockopt):
    return daemon_hook_fake_getsockopt((int)args[0], (int)args[1], (int)args[2], (void *)args[3], (socklen_t*)args[4]);
  case SCMP_SYS(bind):
    return daemon_hook_fake_bind((int)args[0], (void *)args[1], (socklen_t)args[2]);
  case SCMP_SYS(listen):
    return daemon_hook_fake_listen((int)args[0], (int)args[1]);
  case SCMP_SYS(accept):
    return daemon_hook_fake_accept4((int)args[0], (struct sockaddr *)args[1], (socklen_t *)args[2], 0);
  case SCMP_SYS(accept4):
    return daemon_hook_fake_accept4((int)args[0], (struct sockaddr *)args[1], (socklen_t *)args[2], (int)args[3]);
  case SCMP_SYS(getsockname):
    return daemon_hook_fake_getsockname((int)args[0], (struct sockaddr *)args[1], (socklen_t *)args[2]);
  case SCMP_SYS(getpeername):
    return daemon_hook_fake_getpeername((int)args[0], (struct sockaddr *)args[1], (socklen_t *)args[2]);
  case SCMP_SYS(close):
    return daemon_hook_fake_close((int)args[0]);
  case SCMP_SYS(poll):
    return daemon_hook_fake_poll((struct pollfd *)args[0], (nfds_t)args[1], (int)args[2]);
  case SCMP_SYS(select):
    return daemon_hook_fake_select((int)args[0], (fd_set*)args[1], (fd_set*)args[2], (fd_set*)args[3], (struct timeval *)args[4]);
  case SCMP_SYS(fcntl):
    return daemon_hook_fake_fcntl((int)args[0], (int)args[1], (uint64_t)args[2]);
  case SCMP_SYS(ioctl):
    return daemon_hook_fake_ioctl((int)args[0], (int)args[1], (uint64_t)args[2]);
  case SCMP_SYS(recv):
    return daemon_hook_fake_recvfrom((int)args[0], (void *)args[1], (size_t)args[2], (int)args[3], NULL, NULL);
  case SCMP_SYS(recvfrom):
    return daemon_hook_fake_recvfrom((int)args[0], (void *)args[1], (size_t)args[2], (int)args[3], (struct sockaddr*)args[4], (socklen_t*)args[5]);
  case SCMP_SYS(send):
    return daemon_hook_fake_send((int)args[0], (void *)args[1], (size_t)args[2], (int)args[3]);
  case SCMP_SYS(sendto):
    return daemon_hook_fake_sendto((int)args[0], (void *)args[1], (size_t)args[2], (int)args[3], (struct sockaddr*)args[4], (socklen_t*)args[5]);
  case SCMP_SYS(shutdown):
    return daemon_hook_fake_shutdown((int)args[0], (int)args[1]);

  // These syscalls are the time-related syscalls
  case SCMP_SYS(nanosleep):
    return daemon_hook_fake_nanosleep((void *)args[0], (void *)args[1]);

  // these syscalls are implemented in terms of the others or are incredibly simple
  case SCMP_SYS(lseek):
    return -ESPIPE;
  case SCMP_SYS(read):
    return daemon_hook_fake_recvfrom((int)args[0], (void *)args[1], (size_t)args[2], 0, NULL, NULL);
  case SCMP_SYS(write):
    return daemon_hook_fake_send((int)args[0], (void *)args[1], (size_t)args[2], 0);
  case SCMP_SYS(rt_sigaction):
    return daemon_hook_fake_sigaction((int)args[0], (void *)args[1], (void *)args[2]);
  case SCMP_SYS(rt_sigprocmask):
    return daemon_hook_fake_sigprocmask((int)args[0], (void *)args[1], (void *)args[2]);
  case SCMP_SYS(sched_setaffinity):
    warn_printf("Attempt by wrapped process to sched_setaffinity. Ignoring, but could cause bad results...\n");
    return 0; // pretend like we worked :|
  case SCMP_SYS(execve):
    die_printf("Attempt by wrapped process to execve(%s). Death will take me.\n", (char *)args[0]);
  default:
    die_printf("Trapped unhandled syscall %d{%lx, %lx, %lx, %lx, %lx, %lx}\n",
        syscall, args[0], args[1], args[2], args[3], args[4], args[5]);
  }
}

void daemon_hook_handle_sigsys(int sig, siginfo_t *info, void *data) {
  if (die_die_die) {
    kill(getpid(), SIGSYS);
    kill(getpid(), SIGSEGV);
    while (1) { }
  }

  // Check to make sure si_code is 1 for SYS_SECCOMP
  // probably should include the header or something...
  if (info->si_code != SYS_SECCOMP) {
    die_printf("Non-Seccomp SIGSYS!! Something very strange is going on!!\n");
  }

  // this contains our saved syscall arguments, that we're going to rip out.
  ucontext_t* saved_context = (ucontext_t*)data;

#ifdef __x86_64__
  uint64_t args[6];
  int64_t *ret;

  // This information comes from the arch calling conventions in syscall(2)
  args[0] = saved_context->uc_mcontext.gregs[REG_RDI];
  args[1] = saved_context->uc_mcontext.gregs[REG_RSI];
  args[2] = saved_context->uc_mcontext.gregs[REG_RDX];
  args[3] = saved_context->uc_mcontext.gregs[REG_R10];
  args[4] = saved_context->uc_mcontext.gregs[REG_R8];
  args[5] = saved_context->uc_mcontext.gregs[REG_R9];

  ret = (int64_t*)&saved_context->uc_mcontext.gregs[REG_RAX];
#else
#error "Only x86_64 is supported"
#endif

  info_printf("Dispatching syscall %d\n", info->si_syscall);

  // handle clone a bit special, because there's no stdlib function for it
  if (info->si_syscall == SCMP_SYS(clone)) {
     daemon_hook_preclone();
     fake_ptid_location = 0;
     *ret = syscall(SYS_clone, (unsigned long)args[0], (void *)args[1], &fake_ptid_location, (void *)args[3], (unsigned long)args[4]);
     if (args[2] != 0) {
       *(unsigned long*)args[2] = fake_ptid_location;
     }
  } else {
    // dispatch _SANE_ syscalls
    *ret = dispatch_syscall(info->si_syscall, args);
  }

  info_printf("Syscall returned 0x%lx(%ld)\n", *ret, *ret);
}

static void daemon_hook_init_fds(void) {
  int ctr = -1;
  for (int i = 0; i < NUM_DUMMY_FDS; i++) {
    int res = open("/", O_PATH);
    if (res < 0) {
      die_printf("Fake open(O_PATH) in daemon_hook_init failed.\n");
    }
    if (ctr == -1) {
      min_dummy_fd = res;
      ctr = res;
    } else if (res != ctr+1) {
      // TODO: Switch from range comparison to just 16 SCMP_CMP_EQs if this is a problem
      die_printf("Fake open(O_PATH) was not contiguous...?\n");
    } else {
      ctr += 1;
    }
  }
}

static void daemon_hook_init_traps(void) {
  struct sigaction sys_action;
  sys_action.sa_sigaction = daemon_hook_handle_sigsys;
  sigemptyset(&sys_action.sa_mask);
  sys_action.sa_flags = SA_SIGINFO;

  struct sigaction old_action;
  if (sigaction(SIGSYS, &sys_action, &old_action) < 0) {
    die_printf("Failed to sigaction in daemon_hook_init.\n");
  } else if (old_action.sa_handler != SIG_DFL && old_action.sa_handler != SIG_IGN && !getenv("DAEMON_HOOK_FORKSRV_INIT")) {
    // Qemu registers one of these... so meh
    die_printf("Program already had a SIGSYS handler!! Something strange is going on!\n");
  }

  sigemptyset(&passthrough_sigset);
  sigaddset(&passthrough_sigset, SIGSYS);
  if (sigprocmask(SIG_UNBLOCK, &passthrough_sigset, NULL)) {
    die_printf("Failed to sigprocmask unblock SIGSYS.\n");
  }


  // Set affinity to current core only. This is an attempt to try to
  // get a bit more deterministic ordering of operations
  cpu_set_t s;
  CPU_ZERO(&s);
  CPU_SET(sched_getcpu(), &s);
  sched_setaffinity(0, sizeof(s), &s);

  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);

  // Disallow network syscalls that we will be "emulating"
  // list is mostly ripped from http://lxr.free-electrons.com/source/net/socket.c
  int fail = 0;

#define seccomp_rule_add_wrapper(ctx, act, sys, ...) \
  do {\
    if ((fail = seccomp_rule_add(ctx, act, sys, __VA_ARGS__)) < 0) { \
       die_printf("Failed to seccomp_rule_add for syscall(%d)! error=%d, call(%s)\n", sys, fail, #__VA_ARGS__); \
    } \
  } while (0)

// TODO: follow up with someone from libseccomp, about why the range operators don't work here?
#if 0
#define trap_sockfd_arg(syscall, arg) \
  do { \
    seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(syscall), 2, SCMP_CMP(arg, SCMP_CMP_GE, min_dummy_fd), SCMP_CMP(arg, SCMP_CMP_LT, min_dummy_fd + NUM_DUMMY_FDS)); \
  } while (0)
#else
#define trap_sockfd_arg(syscall, arg) \
  do { \
    for (int i = 0; i < NUM_DUMMY_FDS; i++) {\
      seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(syscall), 1, SCMP_CMP(arg, SCMP_CMP_EQ, min_dummy_fd + i)); \
    } \
  } while (0)
#endif
#define trap_sockfd(syscall) trap_sockfd_arg(syscall, 0)
#define trap_sockfd2(syscall) trap_sockfd_arg(syscall, 1)

  // TODO: rewrite this to be a loop and not generate so much code.

  // Trap socket calls for TCP/IP
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(socket), 2, SCMP_A0(SCMP_CMP_EQ, AF_INET), SCMP_A1(SCMP_CMP_MASKED_EQ, 0xFF, SOCK_STREAM));
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(socket), 2, SCMP_A0(SCMP_CMP_EQ, AF_INET6), SCMP_A1(SCMP_CMP_MASKED_EQ, 0xFF, SOCK_STREAM));

  if (daemon_hook_udp) {
    seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(socket), 2, SCMP_A0(SCMP_CMP_EQ, AF_INET), SCMP_A1(SCMP_CMP_MASKED_EQ, 0xFF, SOCK_DGRAM));
    seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(socket), 2, SCMP_A0(SCMP_CMP_EQ, AF_INET6), SCMP_A1(SCMP_CMP_MASKED_EQ, 0xFF, SOCK_DGRAM));
  }

  trap_sockfd(accept);
  trap_sockfd(accept4);
  trap_sockfd(listen);
  trap_sockfd(bind);
  trap_sockfd(getsockname);
  trap_sockfd(connect);
  trap_sockfd(getpeername);
  trap_sockfd(send);
  trap_sockfd(sendto);
  trap_sockfd(recv);
  trap_sockfd(recvfrom);
  trap_sockfd(setsockopt);
  trap_sockfd(getsockopt);
  trap_sockfd(shutdown);
  trap_sockfd(sendmsg);
  trap_sockfd(sendmmsg);
  trap_sockfd(recvmsg);
  trap_sockfd(recvmmsg);

  // I don't really know what to do with this, but I want it to crash
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(socketpair), 1, SCMP_A0(SCMP_CMP_NE, AF_UNIX));

  // We also need to trap generic fd functions, in the case that they're operating on our fake fds
  // We have a 'passthrough' fd table for poll here. This allows our fake handler to call the real poll function
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(poll), 1, SCMP_A0(SCMP_CMP_NE, &passthrough_poll_fds));
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(ppoll), 0);
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(select), 1, SCMP_A1(SCMP_CMP_NE, &passthrough_read_fdset));
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(pselect6), 0);
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(epoll_create), 0);
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(epoll_create1), 0);
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(epoll_ctl), 0);
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(epoll_wait), 0);

  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(fork), 0);
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(vfork), 0);
  // trap calls to clone that are actually forks
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(clone), 2, SCMP_A2(SCMP_CMP_NE, &fake_ptid_location), SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_VM, 0));
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(execve), 0);

  // The next ones are common file descriptor operations that we need to trap if they're on
  // one of our fds
  trap_sockfd(close);
  trap_sockfd(dup);
  trap_sockfd(dup2);
  trap_sockfd2(dup2);
  trap_sockfd(dup3);
  trap_sockfd2(dup3);
  trap_sockfd(fcntl);
  trap_sockfd(ioctl);
  // Note: we (probably?) don't have to trap syscalls like fsync
  // even though they could be used on our file descriptor, they'll fail with EINVAL anyway
  trap_sockfd(lseek);
  trap_sockfd(read);
  trap_sockfd(write);

  // These traps prevent the program from overriding our hooking
  // XXX: Only rt_sigaction (and later down rt_sigtimedwait) are hooked. Work is required to
  // hook sigaction and sigtimedwait, which non X86_64 architectures have
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(rt_sigaction), 1, SCMP_A0(SCMP_CMP_EQ, SIGSYS));
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(rt_sigprocmask), 1, SCMP_A0(SCMP_CMP_NE, &passthrough_sigset));
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(sched_setaffinity), 0);

  // See time(7) for a list of these.
  // Why does linux have some many timing syscalls?!

  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(time), 0);
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(utime), 0);
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(times), 0);
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(adjtimex), 0);
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(getrusage), 0);
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(getrlimit), 1, SCMP_A0(SCMP_CMP_EQ, RLIMIT_RTTIME));
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(getrlimit), 1, SCMP_A0(SCMP_CMP_EQ, RLIMIT_CPU));
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(rt_sigtimedwait), 0);
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(clock_getres), 0);
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(gettimeofday), 0);
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(settimeofday), 0);
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(nanosleep), 1, SCMP_A0(SCMP_CMP_NE, &passthrough_req_timespec));
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(clock_gettime), 0);
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(clock_nanosleep), 0);
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(alarm), 0);
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(getitimer), 0);
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(timer_create), 0);
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(timerfd_create), 0);

  // In theory we could trap stat, but this seems like an incredibly obscure case, and hard to hook
  // Perhaps also should trap various prctl calls???

  // also trap calls to futex() that a) use a timeout and b) have a non-null timeout
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(futex), 2, SCMP_A1(SCMP_CMP_MASKED_EQ, FUTEX_CMD_MASK, FUTEX_WAIT), SCMP_A4(SCMP_CMP_NE, 0));
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(futex), 2, SCMP_A1(SCMP_CMP_MASKED_EQ, FUTEX_CMD_MASK, FUTEX_LOCK_PI), SCMP_A4(SCMP_CMP_NE, 0));
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(futex), 2, SCMP_A1(SCMP_CMP_MASKED_EQ, FUTEX_CMD_MASK, FUTEX_WAIT_REQUEUE_PI), SCMP_A4(SCMP_CMP_NE, 0));

  // Really only super user can do this...?
  seccomp_rule_add_wrapper(ctx, SCMP_ACT_TRAP, SCMP_SYS(adjtimex), 0);

  if (debug_level > 1) {
    BLUE;
    seccomp_export_pfc(ctx, 2);
    RESET;
  }

  seccomp_load(ctx);
}

void daemon_hook_init_real(void) {
  if (getenv("DAEMON_HOOK_DEBUG")) {
    debug_level = atoi(getenv("DAEMON_HOOK_DEBUG"));
  }

  daemon_hook_udp = !!(getenv("DAEMON_HOOK_UDP"));

  // probably should allow a way to not...
  use_colors = 1;

  daemon_hook_inited = 1;

  daemon_hook_init_tidi();
  daemon_hook_init_fds();
  daemon_hook_init_traps();
  daemon_hook_init_transcript();
}

void daemon_hook_init(void) {
  if (getenv("DAEMON_HOOK_ONLY")) {
    if (strcmp(getenv("DAEMON_HOOK_ONLY"), program_invocation_short_name)) {
      return;
    }
  }

  if (getenv("DAEMON_HOOK_FORKSRV_INIT")) {
    return;
  }

  if (!getenv("DAEMON_HOOK_FORSRV_INIT") && !getenv("AFL_NO_FORKSRV") &&
      (!strcmp(program_invocation_short_name, "afl-qemu-trace"))) {
    warn_printf("Looks like we're running in afl-qemu-trace with forkserver, but DAEMON_HOOK_FORKSRV_INIT isn't specified!!\n");
  }

  daemon_hook_init_real();
}

int close(int fd) {
  if (fd == AFL_FORKSRV_FD && !daemon_hook_inited && getenv("DAEMON_HOOK_FORKSRV_INIT")) {
    if (!getenv("DAEMON_HOOK_ONLY") || !strcmp(getenv("DAEMON_HOOK_ONLY"), program_invocation_short_name)) {
      daemon_hook_init_real();
    }
  }

  int (*original_close)(int);
  original_close = dlsym(RTLD_NEXT, "close");
  return original_close(fd);
}

// Implementing this lets us be used as an LD_AUDIT instead of LD_PRELOAD
int la_version(int a) {
  return a;
}
