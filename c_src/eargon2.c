/*
 * Argon2 password hashing algorithm Erlang NIF
 *
 * Copyright 2018
 * Madalin Grigore-Enescu
 *
 * Copyright 2015
 * Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
 *
 * You may use this work under the terms of a Creative Commons CC0 1.0
 * License/Waiver or the Apache Public License 2.0, at your option. The terms of
 * these licenses can be found at:
 *
 * - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
 * - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0
 *
 * You should have received a copy of both of these licenses along with this
 * software. If not, they may be obtained at the above URLs.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "erl_nif.h"

#include "argon2.h"
#include "encoding.h"
#include "core.h"


