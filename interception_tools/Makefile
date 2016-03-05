CC=gcc
CPP=g++

GLIB_FLAGS = -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include  -lglib-2.0

all: cong_signal_interceptor.so cong_control_interceptor.so

%.so: %.c
	$(CC) -shared -fPIC  $^ -o $@ -ldl -lpthread $(GLIB_FLAGS)

cong_control: cong_control_interceptor.so

capacity_signal: cong_signal_interceptor.so

.PHONY: clean all

clean:
	rm -f *.so
