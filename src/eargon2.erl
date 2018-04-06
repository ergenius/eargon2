%%%-------------------------------------------------------------------
%%% eArgon2 - Erlang Argon2 password hashing
%%%
%%% Copyright 2018 Madalin Grigore-Enescu
%%%
%%% You may use this work under the terms of a Creative Commons CC0 1.0
%%% License/Waiver or the Apache Public License 2.0, at your option. The terms of
%%% these licenses can be found at:
%%%
%%% - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
%%% - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0
%%%
%%% You should have received a copy of both of these licenses along with this
%%% software. If not, they may be obtained at the above URLs.
%%%-------------------------------------------------------------------

-module(eargon2).
-author("Madalin Grigore-Enescu").

-include("eargon2.hrl").

-on_load(init/0).

%% API exports
-export([

    hash_2i_encoded/6, hash_2i_encoded/7,
    hash_2d_encoded/6, hash_2d_encoded/7,
    hash_2id_encoded/6, hash_2id_encoded/7,

    hash_2i_raw/6, hash_2i_raw/7,
    hash_2d_raw/6, hash_2d_raw/7,
    hash_2id_raw/6, hash_2id_raw/7,

    hash/8, hash/9,

    verify_2i/2,
    verify_2d/2,
    verify_2id/2,
    verify/3,

    error_message/1,
    encodedlen/6

    ]).

%% Not loaded macro
-define(NIF_LIB_NOT_LOADED(), exit({nif_library_not_loaded, [{module, ?MODULE}, {line, ?LINE}]})).

%% eArgon2 C library name
-define(EARGON2_CLIB_NAME, eargon2).

%%====================================================================
%% INIT
%%====================================================================

%% Loads and links eArgon2 dynamic library containing native implemented functions (NIFs)
init() ->
    SoName = case code:priv_dir(?MODULE) of
                 {error, bad_name} ->
                     case filelib:is_dir(filename:join(["..", priv])) of
                         true ->
                             filename:join(["..", priv, ?EARGON2_CLIB_NAME]);
                         _ ->
                             filename:join([priv, ?EARGON2_CLIB_NAME])
                     end;
                 Dir ->
                     filename:join(Dir, ?EARGON2_CLIB_NAME)
             end,
    erlang:load_nif(SoName, 0).

%%====================================================================
%% HASH
%%====================================================================

%% Hashes a password with Argon2i, producing an encoded hash
%% Different parallelism levels will give different results
hash_2i_encoded(TCost, MCost, Parallelism, Pwd, Salt, HashLen) ->
    hash(TCost, MCost, Parallelism, Pwd, Salt, HashLen,
                ?EARGON2_RESULT_TYPE_ENCODED, ?EARGON2_HASH_TYPE_ARGON2_I, ?EARGON2_VERSION_NUMBER).

hash_2i_encoded(TCost, MCost, Parallelism, Pwd, Salt, HashLen, Version) ->
    hash(TCost, MCost, Parallelism, Pwd, Salt, HashLen,
                ?EARGON2_RESULT_TYPE_ENCODED, ?EARGON2_HASH_TYPE_ARGON2_I, Version).

hash_2d_encoded(TCost, MCost, Parallelism, Pwd, Salt, HashLen) ->
    hash(TCost, MCost, Parallelism, Pwd, Salt, HashLen,
                ?EARGON2_RESULT_TYPE_ENCODED, ?EARGON2_HASH_TYPE_ARGON2_D, ?EARGON2_VERSION_NUMBER).

hash_2d_encoded(TCost, MCost, Parallelism, Pwd, Salt, HashLen, Version) ->
    hash(TCost, MCost, Parallelism, Pwd, Salt, HashLen,
                ?EARGON2_RESULT_TYPE_ENCODED, ?EARGON2_HASH_TYPE_ARGON2_D, Version).

hash_2id_encoded(TCost, MCost, Parallelism, Pwd, Salt, HashLen) ->
    hash(TCost, MCost, Parallelism, Pwd, Salt, HashLen,
                ?EARGON2_RESULT_TYPE_ENCODED, ?EARGON2_HASH_TYPE_ARGON2_ID, ?EARGON2_VERSION_NUMBER).

hash_2id_encoded(TCost, MCost, Parallelism, Pwd, Salt, HashLen, Version) ->
    hash(TCost, MCost, Parallelism, Pwd, Salt, HashLen,
                ?EARGON2_RESULT_TYPE_ENCODED, ?EARGON2_HASH_TYPE_ARGON2_ID, Version).

hash_2i_raw(TCost, MCost, Parallelism, Pwd, Salt, HashLen) ->
    hash(TCost, MCost, Parallelism, Pwd, Salt, HashLen,
         ?EARGON2_RESULT_TYPE_RAW, ?EARGON2_HASH_TYPE_ARGON2_I, ?EARGON2_VERSION_NUMBER).

hash_2i_raw(TCost, MCost, Parallelism, Pwd, Salt, HashLen, Version) ->
    hash(TCost, MCost, Parallelism, Pwd, Salt, HashLen,
         ?EARGON2_RESULT_TYPE_RAW, ?EARGON2_HASH_TYPE_ARGON2_I, Version).

hash_2d_raw(TCost, MCost, Parallelism, Pwd, Salt, HashLen) ->
    hash(TCost, MCost, Parallelism, Pwd, Salt, HashLen,
         ?EARGON2_RESULT_TYPE_RAW, ?EARGON2_HASH_TYPE_ARGON2_D, ?EARGON2_VERSION_NUMBER).

hash_2d_raw(TCost, MCost, Parallelism, Pwd, Salt, HashLen, Version) ->
    hash(TCost, MCost, Parallelism, Pwd, Salt, HashLen,
         ?EARGON2_RESULT_TYPE_RAW, ?EARGON2_HASH_TYPE_ARGON2_D, Version).

hash_2id_raw(TCost, MCost, Parallelism, Pwd, Salt, HashLen) ->
    hash(TCost, MCost, Parallelism, Pwd, Salt, HashLen,
         ?EARGON2_RESULT_TYPE_RAW, ?EARGON2_HASH_TYPE_ARGON2_ID, ?EARGON2_VERSION_NUMBER).

hash_2id_raw(TCost, MCost, Parallelism, Pwd, Salt, HashLen, Version) ->
    hash(TCost, MCost, Parallelism, Pwd, Salt, HashLen,
         ?EARGON2_RESULT_TYPE_RAW, ?EARGON2_HASH_TYPE_ARGON2_ID, Version).

hash(TCost, MCost, Parallelism, Pwd, Salt, HashLen, ResultType, Type) ->
    hash(TCost, MCost, Parallelism, Pwd, Salt, HashLen, ResultType, Type, ?EARGON2_VERSION_NUMBER).

hash(TCost, MCost, Parallelism, Pwd, Salt, HashLen, ResultType, Type, Version) ->

    ?NIF_LIB_NOT_LOADED().

%%====================================================================
%% VERIFY
%%====================================================================

%% Verifies a password against an encoded string
verify_2i(Encoded, Pwd) -> verify(Encoded, Pwd, ?EARGON2_HASH_TYPE_ARGON2_I).

verify_2d(Encoded, Pwd) -> verify(Encoded, Pwd, ?EARGON2_HASH_TYPE_ARGON2_D).

verify_2id(Encoded, Pwd) -> verify(Encoded, Pwd, ?EARGON2_HASH_TYPE_ARGON2_ID).

verify(Encoded, Pwd, Type) ->

    ?NIF_LIB_NOT_LOADED().

%%====================================================================
%% OTHER
%%====================================================================

%% Returns the error message associated with the given error code
error_message(?EARGON2_ERROR_CODE_OK) -> "OK";
error_message(?EARGON2_ERROR_CODE_NIF_BADARG) -> "Bad NIF arguments";
error_message(?EARGON2_ERROR_CODE_OUTPUT_PTR_NULL) -> "Output pointer is NULL";
error_message(?EARGON2_ERROR_CODE_OUTPUT_TOO_SHORT) -> "Output is too short";
error_message(?EARGON2_ERROR_CODE_OUTPUT_TOO_LONG) -> "Output is too long";
error_message(?EARGON2_ERROR_CODE_PWD_TOO_SHORT) -> "Password is too short";
error_message(?EARGON2_ERROR_CODE_PWD_TOO_LONG) -> "Password is too long";
error_message(?EARGON2_ERROR_CODE_SALT_TOO_SHORT) -> "Salt is too short";
error_message(?EARGON2_ERROR_CODE_SALT_TOO_LONG) -> "Salt is too long";
error_message(?EARGON2_ERROR_CODE_AD_TOO_SHORT) -> "Associated data is too short";
error_message(?EARGON2_ERROR_CODE_AD_TOO_LONG) -> "Associated data is too long";
error_message(?EARGON2_ERROR_CODE_SECRET_TOO_SHORT) -> "Secret is too short";
error_message(?EARGON2_ERROR_CODE_SECRET_TOO_LONG) -> "Secret is too long";
error_message(?EARGON2_ERROR_CODE_TIME_TOO_SMALL) -> "Time cost is too small";
error_message(?EARGON2_ERROR_CODE_TIME_TOO_LARGE) -> "Time cost is too large";
error_message(?EARGON2_ERROR_CODE_MEMORY_TOO_LITTLE) -> "Memory cost is too small";
error_message(?EARGON2_ERROR_CODE_MEMORY_TOO_MUCH) -> "Memory cost is too large";
error_message(?EARGON2_ERROR_CODE_LANES_TOO_FEW) -> "Too few lanes";
error_message(?EARGON2_ERROR_CODE_LANES_TOO_MANY) -> "Too many lanes";
error_message(?EARGON2_ERROR_CODE_PWD_PTR_MISMATCH) -> "Password pointer is NULL, but password length is not 0";
error_message(?EARGON2_ERROR_CODE_SALT_PTR_MISMATCH) -> "Salt pointer is NULL, but salt length is not 0";
error_message(?EARGON2_ERROR_CODE_SECRET_PTR_MISMATCH) -> "Secret pointer is NULL, but secret length is not 0";
error_message(?EARGON2_ERROR_CODE_AD_PTR_MISMATCH) -> "Associated data pointer is NULL, but ad length is not 0";
error_message(?EARGON2_ERROR_CODE_MEMORY_ALLOCATION_ERROR) -> "Memory allocation error";
error_message(?EARGON2_ERROR_CODE_FREE_MEMORY_CBK_NULL) -> "The free memory callback is NULL";
error_message(?EARGON2_ERROR_CODE_ALLOCATE_MEMORY_CBK_NULL) -> "The allocate memory callback is NULL";
error_message(?EARGON2_ERROR_CODE_INCORRECT_PARAMETER) -> "Argon2_Context context is NULL";
error_message(?EARGON2_ERROR_CODE_INCORRECT_TYPE) -> "There is no such version of Argon2";
error_message(?EARGON2_ERROR_CODE_OUT_PTR_MISMATCH) -> "Output pointer mismatch";
error_message(?EARGON2_ERROR_CODE_THREADS_TOO_FEW) -> "Not enough threads";
error_message(?EARGON2_ERROR_CODE_THREADS_TOO_MANY) -> "Too many threads";
error_message(?EARGON2_ERROR_CODE_MISSING_ARGS) -> "Missing arguments";
error_message(?EARGON2_ERROR_CODE_ENCODING_FAIL) -> "Encoding failed";
error_message(?EARGON2_ERROR_CODE_DECODING_FAIL) -> "Decoding failed";
error_message(?EARGON2_ERROR_CODE_THREAD_FAIL) -> "Threading failure";
error_message(?EARGON2_ERROR_CODE_DECODING_LENGTH_FAIL) -> "Some of encoded parameters are too long or too short";
error_message(?EARGON2_ERROR_CODE_VERIFY_MISMATCH) -> "The password does not match the supplied hash";
error_message(_) -> "Unknown error code".

%% Returns the encoded hash length for the given input parameters
encodedlen(TCost, MCost, Parallelism, Saltlen, HashLen, Type) ->

    ?NIF_LIB_NOT_LOADED().

%%====================================================================
%% RANDOM
%%====================================================================

