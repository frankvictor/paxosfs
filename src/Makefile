CC=gcc
export ROOT := $(shell pwd)
INCLUDEPATH=$(ROOT)/../include
export INSTALLDIR=$(ROOT)/../bin/
vpath %.h $(INCLUDEPATH)
export SUBDIRS = fs 

export CFLAGS= -g -Wall -I$(INCLUDEPATH) -DHAVE_SETXATTR -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=25
export LDFLAGS=-lfuse 

.PHONY: all $(SUBDIRS) clean cleanall mkbin 
all: mkbin $(SUBDIRS)
	@echo -e "[All Done!]"	
$(SUBDIRS):
	$(MAKE) -C $@
clean: 
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir clean; \
	done
mkbin:
	mkdir -p $(INSTALLDIR)
cleanall:
	for dir in $(SUBDIRS); do \
                $(MAKE) -C $$dir clean; \
	done
	rm -f $(INSTALLDIR)/*
	rm -rf $(INSTALLDIR)
