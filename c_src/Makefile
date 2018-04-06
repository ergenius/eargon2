##-------------------------------------------------------------------
## eArgon2 - Erlang Argon2 password hashing
##
## Copyright 2018 Madalin Grigore-Enescu
##
## You may use this work under the terms of a Creative Commons CC0 1.0
## License/Waiver or the Apache Public License 2.0, at your option. The terms of
## these licenses can be found at:
##
## - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
## - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0
##
## You should have received a copy of both of these licenses along with this
## software. If not, they may be obtained at the above URLs.
##-------------------------------------------------------------------

print-%  : ; @echo $* = $($*)

PATH_APPLICATION_C_SRC ?= $(shell pwd)
PATH_APPLICATION ?= $(abspath $(PATH_APPLICATION_C_SRC)/..)
APPLICATION_NAME ?= $(notdir $(PATH_APPLICATION))
APPLICATION_NAME := $(strip $(APPLICATION_NAME))

LIBRARY_NAME ?= $(PATH_APPLICATION)/priv/$(APPLICATION_NAME).so

PATH_ARGON2_SRC ?= $(PATH_APPLICATION)/argon2/src
PATH_ARGON2_INCLUDE ?= $(PATH_APPLICATION)/argon2/include
PATH_ERTS_INCLUDE ?= $(shell erl -noshell -s init stop -eval "io:format(\"~ts/erts-~ts/include/\", [code:root_dir(), erlang:system_info(version)]).")
PATH_ERL_INTERFACE_INCLUDE ?= $(shell erl -noshell -s init stop -eval "io:format(\"~ts\", [code:lib_dir(erl_interface, include)]).")
PATH_ERL_INTERFACE_LIB ?= $(shell erl -noshell -s init stop -eval "io:format(\"~ts\", [code:lib_dir(erl_interface, lib)]).")

CFLAGS_INCLUDE ?= -I$(PATH_ARGON2_SRC) -I$(PATH_ARGON2_INCLUDE) -I$(PATH_ERTS_INCLUDE) -I$(PATH_ERL_INTERFACE_INCLUDE) -I$(PATH_APPLICATION_C_SRC)

SRC = $(PATH_ARGON2_SRC)/argon2.c $(PATH_ARGON2_SRC)/core.c $(PATH_ARGON2_SRC)/blake2/blake2b.c\
      $(PATH_ARGON2_SRC)/thread.c $(PATH_ARGON2_SRC)/encoding.c $(PATH_ARGON2_SRC)/ref.c\
      $(PATH_APPLICATION_C_SRC)/eargon2.c

SYSTEM_INFORMATION := $(shell uname -s)

ifeq ($(SYSTEM_INFORMATION), Linux)
	CC ?= cc
	CFLAGS ?= -pthread -O3 -finline-functions -Wall -g $(CFLAGS_INCLUDE) -shared -fPIC -fvisibility=hidden -Wl,-soname,libargon2.so.0
else ifeq ($(SYSTEM_INFORMATION), Darwin)
	CC ?= cc
	CFLAGS ?= -pthread -O3 -arch x86_64 -finline-functions -Wall -g $(CFLAGS_INCLUDE) -dynamiclib -undefined dynamic_lookup
else ifeq ($(SYSTEM_INFORMATION), FreeBSD))
	CC ?= cc
	CFLAGS ?= -pthread -O3 -finline-functions -Wall -g $(CFLAGS_INCLUDE) -shared -fPIC
endif

all: $(LIBRARY_NAME)

$(LIBRARY_NAME): $(SRC)
	mkdir -p priv
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -f $(LIBRARY_NAME)
