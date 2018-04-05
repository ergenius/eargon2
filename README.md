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
