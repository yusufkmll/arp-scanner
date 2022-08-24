default: build
build: 
	gcc -o arpscanner atomictest.c -lm -pthread
# -g -Wall for detailed information
install:
	gcc -o arpscanner atomictest.c -lm -pthread
	cp arpscanner /usr/bin/
	cp config.txt /etc/arpscanner.conf
config:
	nano /etc/arpscanner.conf
clean: 
	$(RM) /bin/arpscanner
	