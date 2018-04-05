PREFIX:=../
DEST:=$(PREFIX)$(PROJECT)

REBAR=./rebar3

.PHONY: all clean test release-production release-developing

all:
	(cd argon2;make all;cd ..;cp argon2/libargon2.so.1 argon2/libargon2.a priv)
	@$(REBAR) compile

clean:
	(cd argon2;make clean;cd ..;rm -f priv/libargon2.so.1 priv/libargon2.a priv/kat-argon2*)
	@$(REBAR) clean

test:
	@$(REBAR) eunit

release-production:
	@$(REBAR) release -n eargon_developing

release-developing:
	@$(REBAR) release -n eargon_production
