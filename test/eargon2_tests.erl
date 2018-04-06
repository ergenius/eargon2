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

-module(eargon2_tests).
-author("madalin").

-include("eargon2.hrl").
-include_lib("eunit/include/eunit.hrl").

all_test_() ->

    random:seed(erlang:phash2([node()]),
                erlang:monotonic_time(),
                erlang:unique_integer()),

    ?_assert(erlang:is_integer(eargon2:encodedlen(3, 12, 1, 8, 32, ?EARGON2_HASH_TYPE_ARGON2_D))),
    ?_assert(erlang:is_integer(eargon2:encodedlen(3, 12, 1, 8, 32, ?EARGON2_HASH_TYPE_ARGON2_I))),
    ?_assert(erlang:is_integer(eargon2:encodedlen(3, 12, 1, 8, 32, ?EARGON2_HASH_TYPE_ARGON2_ID))),
    ?_assertMatch({ok, _}, eargon2:hash_2i_encoded(3, 12, 1, random_password_valid(), random_seed_valid(), random_hashlen_valid()))
.

%% Generate a random valid password
random_password_valid() ->

    Bytes = random_integer(8, 64),
    base64:encode(crypto:strong_rand_bytes(Bytes)).

%% Generate a random valid seed
random_seed_valid() ->

    Bytes = random_integer(32, 1024),
    base64:encode(crypto:strong_rand_bytes(Bytes)).

%% Generate a random valid seed
random_hashlen_valid() -> random_integer(32, 1024).

%% Generate a random integer number in the specified interval
random_integer(Min, Max) ->

    Diff      = Max-Min,
    Variation = random:uniform(Diff),
    Min+Variation.
