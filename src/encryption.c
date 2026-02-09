#include "../include/encryption.h"

#include <sodium.h>
#include <string.h>

int hash(const char *password, char *out) {
  return crypto_pwhash_str(out, password, strlen(password),
                           crypto_pwhash_OPSLIMIT_INTERACTIVE,
                           crypto_pwhash_MEMLIMIT_INTERACTIVE);
}

int check(const char *password, const char *hash) {
  return crypto_pwhash_str_verify(hash, password, strlen(password));
}
int createPassword(const char *input, char *out) {
  if (hash(input, out) != 0) {
    return -1;
  }
  return 0;
}
