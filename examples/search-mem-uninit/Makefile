CFLAGS := -O0 -g -static -Wl,-static -no-pie
ARCH = mipsel
TRIPLE = $(ARCH)-linux-musl
CC = $(TRIPLE)-cross/bin/$(TRIPLE)-gcc 


example_app: example_app.c
	$(CC) $(CFLAGS) -o $@ $^
	nm example_app >> symbols.txt

toolchain:
	curl -o cc.tgz https://musl.cc/$(TRIPLE)-cross.tgz
	tar xf cc.tgz
