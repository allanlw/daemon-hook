#include "process.h"

#include <sys/wait.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/syscall.h>

int debug_level = 0;
int use_colors = 1;

extern volatile int die_die_die;

void die_error(void) {
  die_die_die = 1;
  kill(getpid(), SIGSYS);
  kill(getpid(), SIGSEGV);
  exit(1);
}

static int dir_length(char *dir) {
  int dir_fd = open(dir, O_RDONLY | O_DIRECTORY);
  if (dir_fd < 0) { return dir_fd; }

  int count = 0;

  char dummy[4096] = {0};
  int res = syscall(SYS_getdents, dir_fd, &dummy, sizeof(dummy));
  if (res < 0) {
    close(dir_fd);
    return res;
  } else if (res == 0) {
    return 0;
  }
  int i = 0;
  unsigned short next = 0;
  while (i < res) {
    next = *(unsigned short *)(dummy + i + sizeof(unsigned short) * 2);
    count += 1;
    i += next;
    if (next == 0) { break; }
  }

  close(dir_fd);
  info_printf("Dir contains %d entries\n", count);
  return count;
}

static int num_child_threads(void) {
  char proc_task_dir[256] = {0};

  if (snprintf(proc_task_dir, sizeof(proc_task_dir), "/proc/%d/task", getpid()) < 0) {
    die_perror("Failed to snprintf in wait_for_all_children_to_die");
  }

  return dir_length(proc_task_dir) - 1;
}


void wait_for_all_children_to_die(void) {
  char proc_task_dir[256] = {0};

  info_printf("Waiting for children to die...\n");

  exit(1);

  while (num_child_threads() > 0) {
    waitpid(-1, NULL, WNOHANG);
  }

  exit(1);
}
