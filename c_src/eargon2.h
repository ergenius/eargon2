#ifndef EARGON2_H
#define EARGON2_H

#include "erl_nif.h"

#define MAP_TYPE_PRESENT \
    ((ERL_NIF_MAJOR_VERSION == 2 && ERL_NIF_MINOR_VERSION >= 6) \
    || (ERL_NIF_MAJOR_VERSION > 2))

typedef struct {
    ERL_NIF_TERM    atom_ok;
    ERL_NIF_TERM    atom_error;
    ERL_NIF_TERM    atom_null;
    ERL_NIF_TERM    atom_true;
    ERL_NIF_TERM    atom_false;
} eargon2_st;

ERL_NIF_TERM make_atom(ErlNifEnv* env, const char* name);
ERL_NIF_TERM make_ok(eargon2_st* st, ErlNifEnv* env, ERL_NIF_TERM data);
ERL_NIF_TERM make_error(eargon2_st* st, ErlNifEnv* env, const char* error);
ERL_NIF_TERM make_obj_error(eargon2_st* st, ErlNifEnv* env, const char* error, ERL_NIF_TERM obj);

#endif // Included EARGON2_H
