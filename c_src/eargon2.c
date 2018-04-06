/*
 * eArgon2 - Erlang Argon2 password hashing
 *
 * Copyright 2018 Madalin Grigore-Enescu
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

#include "erl_nif.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "argon2.h"
#include "encoding.h"
#include "core.h"

typedef enum EArgon2_result_type {
  eargon2_result_raw     	= 0,
  eargon2_result_encoded 	= 1,
  eargon2_result_both    	= 2,
  eargon2_result_num_types  = 3
} eargon2_result_type;

#define EARGON2_IS_VALID_RESULT_TYPE(v) (v < eargon2_result_num_types)
#define EARGON2_IS_VALID_TYPE(v) (v <= Argon2_id)
#define EARGON2_IS_VALID_VERSION(v) (v == ARGON2_VERSION_10 || v == ARGON2_VERSION_13)

#define EARGON2_ERROR_BADARG(env) enif_make_tuple2(env, enif_make_atom(env, "error"), enif_make_int(env, 1))
#define EARGON2_ERROR_TUPLE(env, errorCode) enif_make_tuple2(env, enif_make_atom(env, "error"), enif_make_int(env, errorCode))

static ERL_NIF_TERM argon2_hash_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

	unsigned int t_cost_param;
	unsigned int m_cost_param;
	unsigned int parallelism_param;
	ErlNifBinary pwd_param;
	ErlNifBinary salt_param;
	unsigned int hashlen_param;
	unsigned int result_type_param;
	unsigned int type_param;
	unsigned int version_param;

	char *hash  		= NULL;
	char *encoded 		= NULL;
	size_t encodedlen 	= 0;

    int result;
	ERL_NIF_TERM result_nif;

	if (argc != 9 ||
	    !enif_get_uint(env, argv[0], &t_cost_param) ||
		!enif_get_uint(env, argv[1], &m_cost_param) ||
		!enif_get_uint(env, argv[2], &parallelism_param) ||
		!enif_inspect_binary(env, argv[3], &pwd_param) ||
		!enif_inspect_binary(env, argv[4], &salt_param) ||
		!enif_get_uint(env, argv[5], &hashlen_param) ||
		!enif_get_uint(env, argv[6], &result_type_param) ||
		!enif_get_uint(env, argv[7], &type_param) ||
		!enif_get_uint(env, argv[8], &version_param) ||
		!EARGON2_IS_VALID_RESULT_TYPE(result_type_param) ||
		!EARGON2_IS_VALID_TYPE(type_param) ||
		!EARGON2_IS_VALID_VERSION(version_param)) {

		return EARGON2_ERROR_BADARG(env);

	}

	/* if caller wants raw data */
	if (result_type_param == eargon2_result_raw ||
	    result_type_param == eargon2_result_both) {

		hash = malloc(hashlen_param);
		if (hash == NULL) {
			return EARGON2_ERROR_TUPLE(env, ARGON2_MEMORY_ALLOCATION_ERROR);
		}

	}

	/* if caller wants encoded data */
	if (result_type_param == eargon2_result_encoded ||
	    result_type_param == eargon2_result_both) {

		encodedlen  = argon2_encodedlen((uint32_t)t_cost_param,
        		                     (uint32_t)m_cost_param,
        		                     (uint32_t)parallelism_param,
        		                     (uint32_t)salt_param.size,
        		                     (uint32_t)hashlen_param,
        		                     (argon2_type)type_param);
        encodedlen++;
        encoded = malloc(encodedlen);
        if (encoded == NULL) {
        	free(hash);
        	return EARGON2_ERROR_TUPLE(env, ARGON2_MEMORY_ALLOCATION_ERROR);
        }

	}

	/* call argon2 */
	result = argon2_hash((uint32_t)t_cost_param,
	                     (uint32_t)m_cost_param,
                         (uint32_t)parallelism_param,
                         pwd_param.data,
                         (size_t)pwd_param.size,
                         salt_param.data,
                         (size_t)salt_param.size,
                         hash,
                         (size_t)hashlen_param,
                         encoded,
                         encodedlen,
                         (argon2_type)type_param,
                         (uint32_t)version_param);

	/* check argon2 response */
    if (result == ARGON2_OK) {

		switch (result_type_param) {
			case eargon2_result_raw:
				result_nif = enif_make_tuple2(env,
        			enif_make_atom(env, "ok"),
        			enif_make_string(env, hash, ERL_NIF_LATIN1));
				break;
			case eargon2_result_encoded:
				result_nif = enif_make_tuple2(env,
                    			enif_make_atom(env, "ok"),
                    			enif_make_string(env, encoded, ERL_NIF_LATIN1));
				break;
			case eargon2_result_both:
				result_nif = enif_make_tuple3(env,
        			enif_make_atom(env, "ok"),
        			enif_make_string(env, hash, ERL_NIF_LATIN1),
        			enif_make_string(env, encoded, ERL_NIF_LATIN1));
				break;
			default:
				result_nif = EARGON2_ERROR_BADARG(env);
		}

	} else {

		result_nif = EARGON2_ERROR_TUPLE(env, result);

	}

	// Wipe memory
	if (hash) clear_internal_memory(hash, hashlen_param);
	if (encoded) clear_internal_memory(encoded, encodedlen);

	// Free memory
	free(hash);
	free(encoded);

	return result_nif;

}

static ERL_NIF_TERM argon2_verify_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

	unsigned int encoded_param_len;
	char * encoded;
	ErlNifBinary pwd_param;
	unsigned int type_param;
	int result;

	if (argc != 3 ||
	    !enif_get_list_length(env, argv[0], &encoded_param_len) ||
	    !enif_inspect_binary(env, argv[1], &pwd_param) ||
        !enif_get_uint(env, argv[2], &type_param) ||
        !EARGON2_IS_VALID_TYPE(type_param)) {

        return EARGON2_ERROR_BADARG(env);

	}

	encoded_param_len++;
	encoded = malloc(encoded_param_len);
    if (encoded == NULL) {
       	return EARGON2_ERROR_TUPLE(env, ARGON2_MEMORY_ALLOCATION_ERROR);
    }

	if (!enif_get_string(env, argv[0], encoded, encoded_param_len, ERL_NIF_LATIN1)) {

		clear_internal_memory(encoded, encoded_param_len);
		free(encoded);
		return EARGON2_ERROR_BADARG(env);

	}

	result = argon2_verify(encoded, pwd_param.data, (size_t)pwd_param.size, (argon2_type)type_param);
	clear_internal_memory(encoded, encoded_param_len);
	free(encoded);

	if (result == ARGON2_OK) {
		return enif_make_atom(env, "ok");
	} else {
		return EARGON2_ERROR_TUPLE(env, result);
	}

}

static ERL_NIF_TERM argon2_encodedlen_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {

    unsigned int t_cost_param;
    unsigned int m_cost_param;
    unsigned int parallelism_param;
    unsigned int saltlen_param;
    unsigned int hashlen_param;
    unsigned int type_param;
	size_t result;

	if (argc != 6 ||
	    !enif_get_uint(env, argv[0], &t_cost_param) ||
		!enif_get_uint(env, argv[1], &m_cost_param) ||
		!enif_get_uint(env, argv[2], &parallelism_param) ||
		!enif_get_uint(env, argv[3], &saltlen_param) ||
		!enif_get_uint(env, argv[4], &hashlen_param) ||
		!enif_get_uint(env, argv[5], &type_param) ||
		!EARGON2_IS_VALID_TYPE(type_param)) {

		return EARGON2_ERROR_BADARG(env);

	}

	result  = argon2_encodedlen((uint32_t)t_cost_param,
		                     (uint32_t)m_cost_param,
		                     (uint32_t)parallelism_param,
		                     (uint32_t)saltlen_param,
		                     (uint32_t)hashlen_param,
		                     (argon2_type)type_param);

	return enif_make_int(env, (int)result);

}

/**
* Load is called when the NIF library is loaded and no previously loaded library exists for this module.
*
* @param priv_data can be set to point to some private data if the library needs to keep a state between NIF calls.
* enif_priv_data returns this pointer. priv_data is initialized to NULL when load is called.
* @param load_info is the second argument to erlang:load_nif/2.
*
* The library fails to load if load returns anything other than 0.
*/
static int on_load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info) {
    return 0;
}

/**
* Upgrade is called when the NIF library is loaded and there is old code of this module with a loaded NIF library.
*
* Works as load, except that *old_priv_data already contains the value set by the last call to load or upgrade for the old module code.
*/
static int on_upgrade(ErlNifEnv* env, void** priv_data, void** old_priv_data, ERL_NIF_TERM load_info) {
    return 0;
}

/**
* Unload is called when the module code that the NIF library belongs to is purged as old.
* New code of the same module may or may not exist.
*/
static void on_unload(ErlNifEnv* env, void* priv_data) {}

static ErlNifFunc nif_functions[] = {
    {"hash", 9, argon2_hash_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
	{"verify", 3, argon2_verify_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"encodedlen", 6, argon2_encodedlen_nif, 0}
};

ERL_NIF_INIT(eargon2, nif_functions, &on_load, NULL, &on_upgrade, &on_unload);
