#ifndef FIRST_C_PROJECT_ENCRYPTION_H
#define FIRST_C_PROJECT_ENCRYPTION_H
#include <sodium.h>

int hash(const char *password, char *out, size_t len);
int check(const char *password, const char *hash, size_t len);

int createPassword(const char *input, char *out, size_t len);

#endif  // FIRST_C_PROJECT_ENCRYPTION_H
