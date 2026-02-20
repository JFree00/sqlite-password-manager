#include "../include/encryption.h"

#include <stdlib.h>
#include <string.h>
static int use_fast_pwhash(void) {
  const char *value = getenv("PWHASH_FAST");
  return value != NULL && value[0] != '\0' && strcmp(value, "0") != 0;
}
/// Must be used prior to  secure_* functions. Locks input memory
int secure_buf_lock(secure_buf *sb, char *buf, size_t len) {
  if (!sb || !buf || len == 0) {
    return -1;
  }
  if (sodium_mlock(buf, len) != 0) {
    return -1;
  }
  sb->buf = buf;
  sb->len = len;
  sb->magic = SECURE_BUF_MAGIC;
  return 0;
}
/// Must be used prior to secure_* functions. Unlocks input memory
int secure_buf_unlock(secure_buf *sb) {
  if (!sb || sb->magic != SECURE_BUF_MAGIC || !sb->buf || sb->len == 0) {
    return -1;
  }
  if (sodium_munlock(sb->buf, sb->len) != 0) {
    return -1;
  }
  sb->buf = nullptr;
  sb->len = 0;
  sb->magic = 0;
  return 0;
}
/// Get a hash for the passed password.
int hash(const char *password, char *out) {
  unsigned long long opslimit = crypto_pwhash_OPSLIMIT_INTERACTIVE;
  size_t memlimit = crypto_pwhash_MEMLIMIT_INTERACTIVE;
  if (use_fast_pwhash()) {
    opslimit = crypto_pwhash_OPSLIMIT_MIN;
    memlimit = crypto_pwhash_MEMLIMIT_MIN;
  }

  return crypto_pwhash_str(out, password, strlen(password), opslimit, memlimit);
}
/// Check a hash against the provided password.
int check(const char *password, const char *hash) {
  return crypto_pwhash_str_verify(hash, password, strlen(password));
}
/// Get a hash for the value stored in the secure-buf. Only work with secure
/// memory.
int hash_secure(const secure_buf *sb, char *out) {
  if (!sb || sb->magic != SECURE_BUF_MAGIC || !sb->buf || sb->len == 0) {
    return -1;
  }
  return hash(sb->buf, out);
}
/// Check a hash against the value stored in the secure-buf. Only work with
/// secure memory.
int check_secure(const secure_buf *sb, const char *hash_value) {
  if (!sb || sb->magic != SECURE_BUF_MAGIC || !sb->buf || sb->len == 0) {
    return -1;
  }
  return check(sb->buf, hash_value);
}

int createPassword(const char *input, char *out) {
  if (hash(input, out) != 0) {
    return -1;
  }
  return 0;
}
