#ifndef FIRST_C_PROJECT_ENCRYPTION_H
#define FIRST_C_PROJECT_ENCRYPTION_H
#include <sodium.h>

#define SECURE_BUF_MAGIC 0x53454355u

typedef struct secure_buf {
  char *buf;
  size_t len;
  unsigned int magic;
} secure_buf;

int secure_buf_lock(secure_buf *sb, char *buf, size_t len);
int secure_buf_unlock(secure_buf *sb);

int hash(const char *password, char *out);
int check(const char *password, const char *hash);
int hash_secure(const secure_buf *sb, char *out);
int check_secure(const secure_buf *sb, const char *hash);

int createPassword(const char *input, char *out);

#endif  // FIRST_C_PROJECT_ENCRYPTION_H
