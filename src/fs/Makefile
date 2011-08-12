#include ../Rules
all: dserver dclient

clean:
	rm -f *.o server client dserver dclient

#server: server.o common.o 

#client: client.o corefs.o common.o

dserver: server.o common.o dummy_mod.o list.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@
	cp $@ $(INSTALLDIR)
	@echo -e "[Server linked]\n"

dclient: client.o corefs.o common.o dummy_mod.o list.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@
	cp $@ $(INSTALLDIR)
	@echo -e "[Client linked]\n"
