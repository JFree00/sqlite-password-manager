#ifndef FIRST_C_PROJECT_ENCRYPTION_H
#define FIRST_C_PROJECT_ENCRYPTION_H

int hash(const char *password, char *out);

int check(const char *password, const char *hash);

#endif //FIRST_C_PROJECT_ENCRYPTION_H
