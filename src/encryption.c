#include "../include/encryption.h"

#include <stdlib.h>
#include <string.h>

static int use_fast_pwhash(void) {
  const char *value = getenv("PWHASH_FAST");
  return value != NULL && value[0] != '\0' && strcmp(value, "0") != 0;
}

int hash(const char *password, char *out) {
  unsigned long long opslimit = crypto_pwhash_OPSLIMIT_INTERACTIVE;
  size_t memlimit = crypto_pwhash_MEMLIMIT_INTERACTIVE;
  if (use_fast_pwhash()) {
    opslimit = crypto_pwhash_OPSLIMIT_MIN;
    memlimit = crypto_pwhash_MEMLIMIT_MIN;
  }

  return crypto_pwhash_str(out, password, strlen(password), opslimit, memlimit);
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
