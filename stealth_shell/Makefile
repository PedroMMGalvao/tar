CC    = gcc
CLANG = clang

CFLAGS  = -Wall -Wextra -O2 -D_GNU_SOURCE
LDFLAGS = -lxdp -lbpf -lssl -lcrypto

BPF_CFLAGS = -O2 -g -target bpf -D__BPF_TRACING__ \
             -I/usr/include/x86_64-linux-gnu        \
             -I/usr/include

EXEC    = stealth_shell_xdp
SRCS    = stealth_net.c stealth_crypto.c stealth_shell.c
OBJS    = $(SRCS:.c=.o)
BPF_SRC = xdp/xdp_kern.c
BPF_OBJ = xdp/xdp_prog.o

.PHONY: all clean

all: $(BPF_OBJ) $(EXEC)

$(BPF_OBJ): $(BPF_SRC)
	@echo "[CLANG-BPF] Compiling $< → $@"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

%.o: %.c
	@echo "[CC] Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

$(EXEC): $(OBJS)
	@echo "[LINK] Linking $(EXEC)..."
	$(CC) $(OBJS) -o $(EXEC) $(LDFLAGS)

clean:
	@echo "[CLEAN]"
	rm -f $(OBJS) $(EXEC) $(BPF_OBJ)
