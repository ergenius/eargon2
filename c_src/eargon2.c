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

#include "eargon2.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "argon2.h"
#include "encoding.h"
#include "core.h"

/**
* Load is called when the NIF library is loaded and no previously loaded library exists for this module.
*
* @param priv_data can be set to point to some private data if the library needs to keep a state between NIF calls.
* enif_priv_data returns this pointer. priv_data is initialized to NULL when load is called.
* @param load_info is the second argument to erlang:load_nif/2.
*
* The library fails to load if load returns anything other than 0.
*/
int on_load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info)
{
    return 0;
}

/**
* Upgrade is called when the NIF library is loaded and there is old code of this module with a loaded NIF library.
*
* Works as load, except that *old_priv_data already contains the value set by the last call to load or upgrade for the old module code.
*/
int on_upgrade(ErlNifEnv* env, void** priv_data, void** old_priv_data, ERL_NIF_TERM load_info)
{
    return 0;
}

/**
* Unload is called when the module code that the NIF library belongs to is purged as old.
* New code of the same module may or may not exist.
*/
int on_unload(ErlNifEnv* env, void* priv_data)
{
    return 0;
}

static ErlNifFunc nif_functions[] = {
    {"test", 1, test}
};

ERL_NIF_INIT(eargon2, nif_functions, &on_load, NULL, &on_upgrade, &on_unload);
