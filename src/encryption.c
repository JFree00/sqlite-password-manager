#include "../include/encryption.h"

#include <stdlib.h>
#include <string.h>
static int use_fast_pwhash(void) {
  const char *value = getenv("PWHASH_FAST");
  return value != NULL && value[0] != '\0' && strcmp(value, "0") != 0;
}

int hash(const char *password, char *out, size_t len) {
  unsigned long long opslimit = crypto_pwhash_OPSLIMIT_INTERACTIVE;
  size_t memlimit = crypto_pwhash_MEMLIMIT_INTERACTIVE;
  if (use_fast_pwhash()) {
    opslimit = crypto_pwhash_OPSLIMIT_MIN;
    memlimit = crypto_pwhash_MEMLIMIT_MIN;
  }

  int pwhash_str =
      crypto_pwhash_str(out, password, strlen(password), opslimit, memlimit);
  sodium_munlock(password, len);
  return pwhash_str;
}

int check(const char *password, const char *hash, size_t len) {
  int pwhash_str_verify =
      crypto_pwhash_str_verify(hash, password, strlen(password));
  sodium_munlock(password, len);
  return pwhash_str_verify;
}
int createPassword(const char *input, char *out, size_t len) {
  if (hash(input, out, len) != 0) {
    return -1;
  }
  return 0;
}
