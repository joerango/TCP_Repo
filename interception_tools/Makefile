CC=gcc

%.so: %.c
	gcc -shared -fPIC  $^ -o $@ -ldl

cong_control: cong_control_interceptor.so

.PHONY: clean

clean:
	rm -f *.so
