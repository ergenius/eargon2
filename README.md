# eArgon2

Argon2 password hashing wrapper for Erlang.

[![Build Status](https://api.travis-ci.org/ergenius/eargon2.svg?branch=master)](https://travis-ci.org/ergenius/eargon2)

# Argon2

Argon2 is a password-hashing function that summarizes the state of the
art in the design of memory-hard functions and can be used to hash
passwords for credential storage, key derivation, or other applications.

It has a simple design aimed at the highest memory filling rate and
effective use of multiple computing units, while still providing defense
against tradeoff attacks (by exploiting the cache and memory organization
of the recent processors).

The [Argon2 document](https://github.com/ergenius/phc-winner-argon2/blob/master/argon2-specs.pdf) gives detailed specs and design
rationale.

## Erlang versions supported

eArgon2 supports OTP release 20 and later with dirty scheduler enabled.

This is because eArgon2 is using ERL_NIF_DIRTY_JOB_CPU_BOUND. However we are working on a new version that will bypass this limitation.

Dirty NIF support is available only when the emulator is configured with dirty scheduler support. 

As of ERTS version 9.0, dirty scheduler support is enabled by default on the runtime system with SMP support. 

The Erlang runtime without SMP support does not support dirty schedulers even when the dirty scheduler support is explicitly enabled. To check at runtime for the presence of dirty scheduler threads, code can use the enif_system_info() API function.

## Getting eArgon2 and Compiling

Install OTP release 20 or later. Install all common Development Tools (make, gcc).

    > git clone https://github.com/ergenius/eargon2.git eargon2
    > cd eargon2
    > git submodule update --init --recursive
    > make
    
## Quick usage
    
    %% Don't forget to include eargon2.hrl in your erlang module
    %% for getting access to all eargon2 definitions.
    include_lib("eargon2.hrl").
    
    %% Hash
    HashResult = eargon2:hash(TCost, MCost, Parallelism, Pwd, Salt, HashLen, ?EARGON2_RESULT_TYPE_BOTH, ?EARGON2_HASH_TYPE_ARGON2_D, ?EARGON2_VERSION_NUMBER);
    case HashResult of 
    	{ok, RawHash, EncodedHash} -> do_something;
    	{error, ErrorCode} -> do_nothing
    end.	
    
    %% Verify
    case eargon2:verify(EncodedHash, Pwd) of 
    	ok -> do_something;
    	{error, ErrorCode} -> stop_doing_anything
    end.	
    
## Motivation

Creating a new Cryptocurrency written in Erlang.

## Project roadmap

1. Continuously fix bugs and tune performance.
2. Write more testing units.
3. Finish and improve documentation.
4. Find alternatives for older Erlang versions not supporting ERL_NIF_DIRTY_JOB_CPU_BOUND
5. Update project when Argon2 library is updated.

## Intellectual property

Except for the components listed below, the Erlang Argon2 wrapper code 
included in this repository is copyright (c) 2018 Madalin Grigore-Enescu
and dual licensed under the
[CC0 License](https://creativecommons.org/about/cc0) and the
[Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0). For more info
see the LICENSE file.

The C implementation of Argon2 is copyright (c) 2015 Daniel Dinu, Dmitry Khovratovich (main
authors), Jean-Philippe Aumasson and Samuel Neves, and dual licensed under the
[CC0 License](https://creativecommons.org/about/cc0) and the
[Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0).

The string encoding routines in [`argon2/src/encoding.c`](https://github.com/ergenius/phc-winner-argon2/blob/master/src/encoding.c) are
copyright (c) 2015 Thomas Pornin, and under
[CC0 License](https://creativecommons.org/about/cc0).

The BLAKE2 code in [`argon2/src/blake2/`](https://github.com/ergenius/phc-winner-argon2/tree/master/src/blake2) is copyright (c) Samuel
Neves, 2013-2015, and under
[CC0 License](https://creativecommons.org/about/cc0).

All licenses are therefore GPL-compatible.
