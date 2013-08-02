CFLAGS=-g -Wall -Werror -D_GNU_SOURCE
LDFLAGS=
all:	prowler

prowler: prowler.o session.o proto.o util.o sig.o
	gcc -O3 $(CFLAGS) -o $@ $^ $(LDFLAGS)

%o: %c
	gcc -c $(CFLAGS) -o $@ $<

clean:
	rm -f *.o prowler
