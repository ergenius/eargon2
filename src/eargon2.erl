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

-include("eargon.hrl").

-on_load(init/0).

%% API exports
-export([

    argon2i_hash_encoded/6, argon2i_hash_encoded/7,
    argon2d_hash_encoded/6, argon2d_hash_encoded/7,
    argon2id_hash_encoded/6, argon2id_hash_encoded/7,
    argon2_hash/7, argon2_hash/8,

    argon2i_verify/2,
    argon2d_verify/2,
    argon2id_verify/2,
    argon2_verify/3,

    argon2_error_message/1,
    argon2_encodedlen/6

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
%% @param t_cost Number of iterations
%% @param m_cost Sets memory usage to m_cost kilobytes
%% @param parallelism Number of threads and compute lanes
%% @param pwd Pointer to password
%% @param pwdlen Password size in bytes
%% @param salt Pointer to salt
%% @param saltlen Salt size in bytes
%% @param hashlen Desired length of the hash in bytes
%% @param encoded Buffer where to write the encoded hash
%% @param encodedlen Size of the buffer (thus max size of the encoded hash)
%%
%% Different parallelism levels will give different results
argon2i_hash_encoded(TCost, MCost, Parallelism, Pwd, Salt, HashLen) ->
    argon2_hash(TCost, MCost, Parallelism, Pwd, Salt, HashLen, ?HASH_TYPE_ARGON2_I, ?ARGON2_VERSION_NUMBER).

argon2i_hash_encoded(TCost, MCost, Parallelism, Pwd, Salt, HashLen, Version) ->
    argon2_hash(TCost, MCost, Parallelism, Pwd, Salt, HashLen, ?HASH_TYPE_ARGON2_I, Version).

argon2d_hash_encoded(TCost, MCost, Parallelism, Pwd, Salt, HashLen) ->
    argon2_hash(TCost, MCost, Parallelism, Pwd, Salt, HashLen, ?HASH_TYPE_ARGON2_D, ?ARGON2_VERSION_NUMBER).

argon2d_hash_encoded(TCost, MCost, Parallelism, Pwd, Salt, HashLen, Version) ->
    argon2_hash(TCost, MCost, Parallelism, Pwd, Salt, HashLen, ?HASH_TYPE_ARGON2_D, Version).

argon2id_hash_encoded(TCost, MCost, Parallelism, Pwd, Salt, HashLen) ->
    argon2_hash(TCost, MCost, Parallelism, Pwd, Salt, HashLen, ?HASH_TYPE_ARGON2_ID, ?ARGON2_VERSION_NUMBER).

argon2id_hash_encoded(TCost, MCost, Parallelism, Pwd, Salt, HashLen, Version) ->
    argon2_hash(TCost, MCost, Parallelism, Pwd, Salt, HashLen, ?HASH_TYPE_ARGON2_ID, Version).

%% generic function underlying the above ones
argon2_hash(TCost, MCost, Parallelism, Pwd, Salt, HashLen, Type) ->
    argon2_hash(TCost, MCost, Parallelism, Pwd, Salt, HashLen, Type, ?ARGON2_VERSION_NUMBER).

argon2_hash(TCost, MCost, Parallelism, Pwd, Salt, HashLen, Type, Version) ->

    ?NIF_LIB_NOT_LOADED().

%%====================================================================
%% VERIFY
%%====================================================================

%% Verifies a password against an encoded string
%% Encoded string is restricted as in validate_inputs()
%% @param encoded String encoding parameters, salt, hash
%% @param pwd Pointer to password
%% @pre   Returns ARGON2_OK if successful
argon2i_verify(Encoded, Pwd) -> argon2_verify(Encoded, Pwd, ?HASH_TYPE_ARGON2_I).

argon2d_verify(Encoded, Pwd) -> argon2_verify(Encoded, Pwd, ?HASH_TYPE_ARGON2_D).

argon2id_verify(Encoded, Pwd) -> argon2_verify(Encoded, Pwd, ?HASH_TYPE_ARGON2_ID).

%% generic function underlying the above ones
argon2_verify(Encoded, Pwd, Type) ->

    ?NIF_LIB_NOT_LOADED().

%%====================================================================
%% OTHER
%%====================================================================

%% Returns the error message associated with the given error code
argon2_error_message(?ARGON2_ERROR_CODE_OK) -> "OK";
argon2_error_message(?ARGON2_ERROR_CODE_OUTPUT_PTR_NULL) -> "Output pointer is NULL";
argon2_error_message(?ARGON2_ERROR_CODE_OUTPUT_TOO_SHORT) -> "Output is too short";
argon2_error_message(?ARGON2_ERROR_CODE_OUTPUT_TOO_LONG) -> "Output is too long";
argon2_error_message(?ARGON2_ERROR_CODE_PWD_TOO_SHORT) -> "Password is too short";
argon2_error_message(?ARGON2_ERROR_CODE_PWD_TOO_LONG) -> "Password is too long";
argon2_error_message(?ARGON2_ERROR_CODE_SALT_TOO_SHORT) -> "Salt is too short";
argon2_error_message(?ARGON2_ERROR_CODE_SALT_TOO_LONG) -> "Salt is too long";
argon2_error_message(?ARGON2_ERROR_CODE_AD_TOO_SHORT) -> "Associated data is too short";
argon2_error_message(?ARGON2_ERROR_CODE_AD_TOO_LONG) -> "Associated data is too long";
argon2_error_message(?ARGON2_ERROR_CODE_SECRET_TOO_SHORT) -> "Secret is too short";
argon2_error_message(?ARGON2_ERROR_CODE_SECRET_TOO_LONG) -> "Secret is too long";
argon2_error_message(?ARGON2_ERROR_CODE_TIME_TOO_SMALL) -> "Time cost is too small";
argon2_error_message(?ARGON2_ERROR_CODE_TIME_TOO_LARGE) -> "Time cost is too large";
argon2_error_message(?ARGON2_ERROR_CODE_MEMORY_TOO_LITTLE) -> "Memory cost is too small";
argon2_error_message(?ARGON2_ERROR_CODE_MEMORY_TOO_MUCH) -> "Memory cost is too large";
argon2_error_message(?ARGON2_ERROR_CODE_LANES_TOO_FEW) -> "Too few lanes";
argon2_error_message(?ARGON2_ERROR_CODE_LANES_TOO_MANY) -> "Too many lanes";
argon2_error_message(?ARGON2_ERROR_CODE_PWD_PTR_MISMATCH) -> "Password pointer is NULL, but password length is not 0";
argon2_error_message(?ARGON2_ERROR_CODE_SALT_PTR_MISMATCH) -> "Salt pointer is NULL, but salt length is not 0";
argon2_error_message(?ARGON2_ERROR_CODE_SECRET_PTR_MISMATCH) -> "Secret pointer is NULL, but secret length is not 0";
argon2_error_message(?ARGON2_ERROR_CODE_AD_PTR_MISMATCH) -> "Associated data pointer is NULL, but ad length is not 0";
argon2_error_message(?ARGON2_ERROR_CODE_MEMORY_ALLOCATION_ERROR) -> "Memory allocation error";
argon2_error_message(?ARGON2_ERROR_CODE_FREE_MEMORY_CBK_NULL) -> "The free memory callback is NULL";
argon2_error_message(?ARGON2_ERROR_CODE_ALLOCATE_MEMORY_CBK_NULL) -> "The allocate memory callback is NULL";
argon2_error_message(?ARGON2_ERROR_CODE_INCORRECT_PARAMETER) -> "Argon2_Context context is NULL";
argon2_error_message(?ARGON2_ERROR_CODE_INCORRECT_TYPE) -> "There is no such version of Argon2";
argon2_error_message(?ARGON2_ERROR_CODE_OUT_PTR_MISMATCH) -> "Output pointer mismatch";
argon2_error_message(?ARGON2_ERROR_CODE_THREADS_TOO_FEW) -> "Not enough threads";
argon2_error_message(?ARGON2_ERROR_CODE_THREADS_TOO_MANY) -> "Too many threads";
argon2_error_message(?ARGON2_ERROR_CODE_MISSING_ARGS) -> "Missing arguments";
argon2_error_message(?ARGON2_ERROR_CODE_ENCODING_FAIL) -> "Encoding failed";
argon2_error_message(?ARGON2_ERROR_CODE_DECODING_FAIL) -> "Decoding failed";
argon2_error_message(?ARGON2_ERROR_CODE_THREAD_FAIL) -> "Threading failure";
argon2_error_message(?ARGON2_ERROR_CODE_DECODING_LENGTH_FAIL) -> "Some of encoded parameters are too long or too short";
argon2_error_message(?ARGON2_ERROR_CODE_VERIFY_MISMATCH) -> "The password does not match the supplied hash";
argon2_error_message(_) -> "Unknown error code".

%% Returns the encoded hash length for the given input parameters
%% @param t_cost  Number of iterations
%% @param m_cost  Memory usage in kibibytes
%% @param parallelism  Number of threads; used to compute lanes
%% @param saltlen  Salt size in bytes
%% @param hashlen  Hash size in bytes
%% @param type The argon2_type that we want the encoded length for
%% @return  The encoded hash length in bytes
argon2_encodedlen(TCost, MCost, Parallelism, Saltlen, HashLen, Type) ->

    ?NIF_LIB_NOT_LOADED().
