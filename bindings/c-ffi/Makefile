CC        = gcc
CFLAGS    = -g
RM        = rm -f
BUILDDIR = target/debug
LDFLAGS = -L$(BUILDDIR) -lrlncffi -lm -ldl -lpthread

default: all

all: example

rust-build:
	cargo build

build-example:
	$(CC) $(CFLAGS) -o example example.c $(LDFLAGS)

example:
	$(MAKE) rust-build
	$(MAKE) build-example

clean:
	cargo clean
	$(RM) example

format:
	clang-format -i --style="{BasedOnStyle: llvm, IndentWidth: 4}" *.c
	cargo fmt

.PHONY: all rust-build build-example example clean format
