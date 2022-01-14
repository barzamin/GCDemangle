SOURCE:=$(wildcard *.c)

sndemangle.so: $(SOURCE)
	$(CC) $^ -o $@ -shared -fPIC -fvisibility=hidden
