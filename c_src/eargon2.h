#ifndef EARGON2_H
#define EARGON2_H

#include "erl_nif.h"

#define MAP_TYPE_PRESENT \
    ((ERL_NIF_MAJOR_VERSION == 2 && ERL_NIF_MINOR_VERSION >= 6) \
    || (ERL_NIF_MAJOR_VERSION > 2))


#endif // Included EARGON2_H
