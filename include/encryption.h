#ifndef FIRST_C_PROJECT_ENCRYPTION_H
#define FIRST_C_PROJECT_ENCRYPTION_H
#include <sodium/core.h>
#include <sodium/crypto_pwhash.h>
int hash(const char *password, char *out);

int check(const char *password, const char *hash);

int createPassword(const char *input, char *out);

#endif  // FIRST_C_PROJECT_ENCRYPTION_H
