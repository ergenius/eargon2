# eArgon2
Argon2 password hashing for Erlang.

Argon2 is a password-hashing function that summarizes the state of the
art in the design of memory-hard functions and can be used to hash
passwords for credential storage, key derivation, or other applications.

It has a simple design aimed at the highest memory filling rate and
effective use of multiple computing units, while still providing defense
against tradeoff attacks (by exploiting the cache and memory organization
of the recent processors).

Argon2 has three variants: Argon2i, Argon2d, and Argon2id. Argon2d is faster
and uses data-depending memory access, which makes it highly resistant
against GPU cracking attacks and suitable for applications with no threats
from side-channel timing attacks (eg. cryptocurrencies). Argon2i instead
uses data-independent memory access, which is preferred for password
hashing and password-based key derivation, but it is slower as it makes
more passes over the memory to protect from tradeoff attacks. Argon2id is a
hybrid of Argon2i and Argon2d, using a combination of data-depending and
data-independent memory accesses, which gives some of Argon2i's resistance to
side-channel cache timing attacks and much of Argon2d's resistance to GPU
cracking attacks.

Argon2i, Argon2d, and Argon2id are parametrized by:

* A **time** cost, which defines the amount of computation realized and
  therefore the execution time, given in number of iterations
* A **memory** cost, which defines the memory usage, given in kibibytes
* A **parallelism** degree, which defines the number of parallel threads

The [Argon2 document](argon2-specs.pdf) gives detailed specs and design
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

The string encoding routines in [`phc-winner-argon2/blob/master/src/encoding.c`](src/encoding.c) are
copyright (c) 2015 Thomas Pornin, and under
[CC0 License](https://creativecommons.org/about/cc0).

The BLAKE2 code in [`phc-winner-argon2/blob/master/src/blake2/`](src/blake2) is copyright (c) Samuel
Neves, 2013-2015, and under
[CC0 License](https://creativecommons.org/about/cc0).

All licenses are therefore GPL-compatible.
