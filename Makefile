CFLAGS=-DLINUX -g


rinetd: rinetd.o match.o
	gcc rinetd.o match.o -o rinetd -lpthread
	
static: rinetd.o match.o
	gcc rinetd.o match.o -o rinetd -static -lpthread
	
install: rinetd
	install -m 755 rinetd /usr/bin
	install -m 644 rinetd.8 /usr/man/man8
	install -m 644 rinetd.service /lib/systemd/system
	install -m 644 rinetd.conf /etc
clean:
	rm -rf *.o