
# Copyright 2010 Google Inc.
# Author: Markus Gutschke
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

VERSION := 1.0

.SUFFIXES: .so

ifeq ($(origin CC), default)
	CC := gcc
endif

DEF_CFLAGS := $(shell [ `uname` = SunOS ] &&                                  \
								echo ' -D_POSIX_PTHREAD_SEMANTICS -D_REENTRANT')              \
							-fvisibility=hidden $(CFLAGS)
DEF_LDFLAGS := $(shell [ `uname` = SunOS ] && echo ' -mimpure-text') $(LDFLAGS)
LDL_LDFLAGS := $(shell $(CC) -shared -ldl -xc -o /dev/null /dev/null          \
											 >/dev/null 2>&1 && echo ' -ldl')

all: google-authenticator pam_google_authenticator.so demo                    \
		 gauth_chktoken gauth_chktoken_testing pam_google_authenticator_unittest

test: pam_google_authenticator_unittest gauth_chktoken_testing
	./pam_google_authenticator_unittest

dist: clean all test
	$(RM) libpam-google-authenticator-$(VERSION)-source.tar.bz2
	tar jfc libpam-google-authenticator-$(VERSION)-source.tar.bz2         \
			--xform="s,^,libpam-google-authenticator-$(VERSION)/,"            \
			--owner=root --group=root                                         \
			*.c *.h *.html Makefile FILEFORMAT README utc-time

install: all
	@dst="`find /lib*/security /lib*/*/security -maxdepth 1               \
							-name pam_unix.so -printf '%H' -quit 2>/dev/null`";       \
	[ -d "$${dst}" ] || dst=/lib/security;                                \
	[ -d "$${dst}" ] || dst=/usr/lib;                                     \
	sudo=; if [ $$(id -u) -ne 0 ]; then                                   \
		echo "You need to be root to install this module.";                 \
		if [ -x /usr/bin/sudo ]; then                                       \
			echo "Invoking sudo:";                                            \
			sudo=sudo;                                                        \
		else                                                                \
			exit 1;                                                           \
		fi;                                                                 \
	fi;                                                                   \
	echo cp pam_google_authenticator.so $${dst};                          \
	tar fc - pam_google_authenticator.so | $${sudo} tar ofxC - $${dst};   \
																																				\
	echo cp google-authenticator /usr/local/bin;                          \
	tar fc - google-authenticator | $${sudo} tar ofxC - /usr/local/bin;   \
	$${sudo} chmod 755 $${dst}/pam_google_authenticator.so                \
										 /usr/local/bin/google-authenticator;               \
																																				\
	echo cp gauth_chktoken /usr/sbin;                                     \
	sudo cp gauth_chktoken /usr/sbin;                                     \
	$${sudo} chmod 6755 /usr/sbin/gauth_chktoken;                         \
																																				\
	echo cp google-authenticator.conf.sample                              \
					/etc/google-authenticator.conf;                               \
	$${sudo} cp google-authenticator.conf.sample                          \
					/etc/google-authenticator.conf;                               \

clean:
	$(RM) *.o *.so core google-authenticator gauth_chktoken demo          \
								 gauth_chktoken_testing                                 \
								 pam_google_authenticator_unittest                      \
								 libpam-google-authenticator-*-source.tar.bz2


google-authenticator.o: google-authenticator.c base32.h hmac.h sha1.h
google-authenticator: google-authenticator.o base32.o hmac.o sha1.o
	$(CC) -g $(DEF_LDFLAGS) -o $@ $+ $(LDL_LDFLAGS)


pam_google_authenticator.o: pam_google_authenticator.c support.h base32.h     \
														hmac.h sha1.h
pam_google_authenticator.so: support.o base32.o hmac.o sha1.o

gauth_chktoken.o: gauth_chktoken.c support.h
gauth_chktoken: gauth_chktoken.o support.o base32.o hmac.o sha1.o
	$(CC) -g $(DEF_LDFLAGS) -o $@ $+ $(LDL_LDFLAGS)

pam_google_authenticator_demo.o: pam_google_authenticator.c support.h         \
																 base32.h hmac.h sha1.h
	# $(CC) -DDEMO --std=gnu99 -Wall -O2 -g -fPIC -c $(DEF_CFLAGS) -o $@ $<
	$(CC) -DDEMO --std=gnu99 -Wall -O0 -g -fPIC -c $(DEF_CFLAGS) -o $@ $<
demo: demo.o pam_google_authenticator_demo.o support.o base32.o hmac.o sha1.o
	$(CC) -g $(DEF_LDFLAGS) -rdynamic -o $@ $+ $(LDL_LDFLAGS)


support_testing.o: support.c support.h base32.h hmac.h sha1.h
	$(CC) -DTESTING --std=gnu99 -Wall -O2 -g -fPIC -c $(DEF_CFLAGS) -o $@ $<

pam_google_authenticator_testing.o: pam_google_authenticator.c support.h      \
																		base32.h hmac.h sha1.h
	$(CC) -DTESTING --std=gnu99 -Wall -O0 -g -fPIC -c $(DEF_CFLAGS) -o $@ $<
pam_google_authenticator_testing.so: support_testing.o base32.o hmac.o sha1.o

gauth_chktoken_testing.o: gauth_chktoken.c support.h
	$(CC) -DTESTING --std=gnu99 -Wall -O0 -g -fPIC -c $(DEF_CFLAGS) -o $@ $<
gauth_chktoken_testing: gauth_chktoken_testing.o support_testing.o base32.o hmac.o sha1.o
	$(CC) -g $(DEF_LDFLAGS) -o $@ $+ $(LDL_LDFLAGS)

pam_google_authenticator_unittest.o: pam_google_authenticator_unittest.c      \
																		 pam_google_authenticator_testing.so      \
																		 base32.h hmac.h sha1.h
pam_google_authenticator_unittest: pam_google_authenticator_unittest.o        \
																	 base32.o hmac.o sha1.o
	$(CC) -g $(DEF_LDFLAGS) -rdynamic -o $@ $+ -lc $(LDL_LDFLAGS)


support.o: support.c support.h base32.h hmac.h sha1.h
base32.o: base32.c base32.h
hmac.o: hmac.c hmac.h sha1.h
sha1.o: sha1.c sha1.h

.c.o:
	# $(CC) --std=gnu99 -Wall -O2 -g -fPIC -c $(DEF_CFLAGS) -o $@ $<
	$(CC) --std=gnu99 -Wall -g -O0 -fno-inline -fPIC -c $(DEF_CFLAGS) -o $@ $<
.o.so:
	$(CC) -shared -g $(DEF_LDFLAGS) -o $@ $+ -lpam
