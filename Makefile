SRC := hook.c transcript.c fake_syscall.c concurrency.c process.c tidi.c

OBJS := $(patsubst %.c,%.o,$(SRC))

CC := gcc
CFLAGS := -Wall -Wextra -fPIC -fpic -D_GNU_SOURCE -Wno-unused-parameter -std=gnu99 -O3 -g
LDFLAGS := -shared -Wl,-init,daemon_hook_init -lseccomp -pthread -ldl

libdaemonhook.so: $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) $(CFLAGS)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS) 

clean:
	rm -rf libdaemonhook.so $(OBJS)
