
CCOPTS=-Wall -Wextra
CC=gcc

.PHONY: clean pristine test

all: testfs

testfs: testfs.o libvvsfs.a
	$(CC) $(CCOPTS) $^ -o $@

testfs.o: testfs.c
	$(CC) $(CCOPTS) -c $< -o $@

image.o: image.c image.h
	$(CC) $(CCOPTS) -c $< -o $@

block.o: block.c block.h
	$(CC) $(CCOPTS) -c $< -o $@

free.0: free.c free.h
	$(CC) $(CCOPTS) -c $< -o $@

inode.o: inode.c inode.h
	$(CC) $(CCOPTS) -c $< -o $@

pack.o: pack.c pack.h
	$(CC) $(CCOPTS) -c $< -o $@

dir.o: dir.c dir.h
	$(CC) $(CCOPTS) -c $< -o $@

libvvsfs.a: block.o image.o free.o inode.o pack.o dir.o
	ar rcs $@ $^

clean:
	rm -f *.o *.img

pristine: clean
	rm -f testfs main *.a

test: testfs.c libvvsfs.a
	@gcc $(CCOPTS) -DCTEST_ENABLE -o testfs $^
	@./testfs
	@rm -f testfs