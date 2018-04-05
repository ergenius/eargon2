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

-author("Madalin Grigore-Enescu").

-define(HASH_TYPE_ARGON2_D,     0).
-define(HASH_TYPE_ARGON2_I,     1).
-define(HASH_TYPE_ARGON2_ID,    2).

-define(ARGON2_VERSION_10,      16#10).
-define(ARGON2_VERSION_13,      16#13).
-define(ARGON2_VERSION_NUMBER,  ?ARGON2_VERSION_13).

-define(ARGON2_ERROR_CODE_OK,                       0).
-define(ARGON2_ERROR_CODE_OUTPUT_PTR_NULL,          -1).
-define(ARGON2_ERROR_CODE_OUTPUT_TOO_SHORT,         -2).
-define(ARGON2_ERROR_CODE_OUTPUT_TOO_LONG,          -3).
-define(ARGON2_ERROR_CODE_PWD_TOO_SHORT,            -4).
-define(ARGON2_ERROR_CODE_PWD_TOO_LONG,             -5).
-define(ARGON2_ERROR_CODE_SALT_TOO_SHORT,           -6).
-define(ARGON2_ERROR_CODE_SALT_TOO_LONG,            -7).
-define(ARGON2_ERROR_CODE_AD_TOO_SHORT,             -8).
-define(ARGON2_ERROR_CODE_AD_TOO_LONG,              -9).
-define(ARGON2_ERROR_CODE_SECRET_TOO_SHORT,         -10).
-define(ARGON2_ERROR_CODE_SECRET_TOO_LONG,          -11).
-define(ARGON2_ERROR_CODE_TIME_TOO_SMALL,           -12).
-define(ARGON2_ERROR_CODE_TIME_TOO_LARGE,           -13).
-define(ARGON2_ERROR_CODE_MEMORY_TOO_LITTLE,        -14).
-define(ARGON2_ERROR_CODE_MEMORY_TOO_MUCH,          -15).
-define(ARGON2_ERROR_CODE_LANES_TOO_FEW,            -16).
-define(ARGON2_ERROR_CODE_LANES_TOO_MANY,           -17).
-define(ARGON2_ERROR_CODE_PWD_PTR_MISMATCH,         -18).
-define(ARGON2_ERROR_CODE_SALT_PTR_MISMATCH,        -19).
-define(ARGON2_ERROR_CODE_SECRET_PTR_MISMATCH,      -20).
-define(ARGON2_ERROR_CODE_AD_PTR_MISMATCH,          -21).
-define(ARGON2_ERROR_CODE_MEMORY_ALLOCATION_ERROR,  -22).
-define(ARGON2_ERROR_CODE_FREE_MEMORY_CBK_NULL,     -23).
-define(ARGON2_ERROR_CODE_ALLOCATE_MEMORY_CBK_NULL, -24).
-define(ARGON2_ERROR_CODE_INCORRECT_PARAMETER,      -25).
-define(ARGON2_ERROR_CODE_INCORRECT_TYPE,           -26).
-define(ARGON2_ERROR_CODE_OUT_PTR_MISMATCH,         -27).
-define(ARGON2_ERROR_CODE_THREADS_TOO_FEW,          -28).
-define(ARGON2_ERROR_CODE_THREADS_TOO_MANY,         -29).
-define(ARGON2_ERROR_CODE_MISSING_ARGS,             -30).
-define(ARGON2_ERROR_CODE_ENCODING_FAIL,            -31).
-define(ARGON2_ERROR_CODE_DECODING_FAIL,            -32).
-define(ARGON2_ERROR_CODE_THREAD_FAIL,              -33).
-define(ARGON2_ERROR_CODE_DECODING_LENGTH_FAIL,     -34).
-define(ARGON2_ERROR_CODE_VERIFY_MISMATCH,          -35).