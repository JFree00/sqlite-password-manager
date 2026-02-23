#include "../include/encryption.h"

#include <stdlib.h>
#include <string.h>

#define ENC_PREFIX "v1:"
#define ENC_NONCE_BYTES crypto_secretbox_NONCEBYTES
#define ENC_MAC_BYTES crypto_secretbox_MACBYTES

static int use_fast_pwhash(void) {
  const char *value = getenv("PWHASH_FAST");
  return value != NULL && value[0] != '\0' && strcmp(value, "0") != 0;
}

/// Must be used prior to *_secure functions. Locks input memory
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
/// Must be used prior to *_secure functions. Unlocks input memory
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
/* Get a hash for the value stored in the secure-buf. Only works with secure
 memory.*/
int hash_secure(const secure_buf *sb, char *out) {
  if (!sb || sb->magic != SECURE_BUF_MAGIC || !sb->buf || sb->len == 0) {
    return -1;
  }
  return hash(sb->buf, out);
}
/* Check a hash against the value stored in the secure-buf. Only works with
 secure memory.*/
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

int is_encrypted_value(const char *value) {
  if (!value) {
    return 0;
  }
  return strncmp(value, ENC_PREFIX, strlen(ENC_PREFIX)) == 0;
}

int derive_wrapping_key(const char *master_key, const unsigned char *salt,
                        size_t salt_len,
                        unsigned char out_key[crypto_secretbox_KEYBYTES]) {
  unsigned long long opslimit = crypto_pwhash_OPSLIMIT_INTERACTIVE;
  size_t memlimit = crypto_pwhash_MEMLIMIT_INTERACTIVE;

  if (!master_key || !salt || !out_key || salt_len != crypto_pwhash_SALTBYTES) {
    return -1;
  }
  if (use_fast_pwhash()) {
    opslimit = crypto_pwhash_OPSLIMIT_MIN;
    memlimit = crypto_pwhash_MEMLIMIT_MIN;
  }

  if (crypto_pwhash(out_key, crypto_secretbox_KEYBYTES, master_key,
                    strlen(master_key), salt, opslimit, memlimit,
                    crypto_pwhash_ALG_DEFAULT) != 0) {
    return -1;
  }
  return 0;
}

/* Encrypt plaintext with XSalsa20-Poly1305 secretbox, prepend nonce, then
 * base64-encode with a "v1:" prefix for storage/versioning. */
int encrypt_with_vault_key(const char *plaintext, const unsigned char *vault_key,
                           size_t vault_key_len, char **out) {
  unsigned char nonce[ENC_NONCE_BYTES];
  unsigned char *ciphertext = nullptr;
  unsigned char *combined = nullptr;
  char *encoded = nullptr;

  if (!plaintext || !vault_key || !out ||
      vault_key_len != crypto_secretbox_KEYBYTES) {
    return -1;
  }

  const size_t plaintext_len = strlen(plaintext);
  const size_t ciphertext_len = plaintext_len + ENC_MAC_BYTES;
  const size_t combined_len = ENC_NONCE_BYTES + ciphertext_len;
  const size_t encoded_len =
      sodium_base64_ENCODED_LEN(combined_len, sodium_base64_VARIANT_ORIGINAL);
  const size_t result_len = strlen(ENC_PREFIX) + encoded_len + 1;

  ciphertext = (unsigned char *)malloc(ciphertext_len);
  combined = (unsigned char *)malloc(combined_len);
  encoded = (char *)malloc(result_len);
  if (!ciphertext || !combined || !encoded) {
    free(ciphertext);
    free(combined);
    free(encoded);
    return -1;
  }

  randombytes_buf(nonce, sizeof(nonce));
  if (crypto_secretbox_easy(ciphertext, (const unsigned char *)plaintext,
                            plaintext_len, nonce, vault_key) != 0) {
    free(ciphertext);
    free(combined);
    free(encoded);
    return -1;
  }

  memcpy(combined, nonce, ENC_NONCE_BYTES);
  memcpy(combined + ENC_NONCE_BYTES, ciphertext, ciphertext_len);

  memcpy(encoded, ENC_PREFIX, strlen(ENC_PREFIX));
  sodium_bin2base64(encoded + strlen(ENC_PREFIX), encoded_len, combined,
                    combined_len, sodium_base64_VARIANT_ORIGINAL);
  *out = encoded;

  free(ciphertext);
  free(combined);
  return 0;
}

/* Parse "v1:"+base64 payload, split nonce/ciphertext, and decrypt via
 * secretbox_open_easy (XSalsa20-Poly1305 authenticated decryption). */
int decrypt_with_vault_key(const char *encoded, const unsigned char *vault_key,
                           size_t vault_key_len, char **out) {
  unsigned char *combined = nullptr;
  unsigned char *plaintext = nullptr;

  if (!encoded || !vault_key || !out ||
      vault_key_len != crypto_secretbox_KEYBYTES) {
    return -1;
  }

  const size_t prefix_len = strlen(ENC_PREFIX);
  if (!is_encrypted_value(encoded)) {
    return -1;
  }

  const char *base64_payload = encoded + prefix_len;
  const size_t payload_len = strlen(base64_payload);
  const size_t max_combined_len = payload_len;
  if (max_combined_len <= ENC_NONCE_BYTES + ENC_MAC_BYTES) {
    return -1;
  }

  combined = (unsigned char *)malloc(max_combined_len);
  if (!combined) {
    return -1;
  }

  size_t combined_len = 0;
  if (sodium_base642bin(combined, max_combined_len, base64_payload, payload_len,
                        nullptr, &combined_len, nullptr,
                        sodium_base64_VARIANT_ORIGINAL) != 0) {
    free(combined);
    return -1;
  }
  if (combined_len <= ENC_NONCE_BYTES + ENC_MAC_BYTES) {
    free(combined);
    return -1;
  }

  const size_t ciphertext_len = combined_len - ENC_NONCE_BYTES;
  const size_t plaintext_len = ciphertext_len - ENC_MAC_BYTES;
  plaintext = (unsigned char *)malloc(plaintext_len + 1);
  if (!plaintext) {
    free(combined);
    return -1;
  }

  if (crypto_secretbox_open_easy(plaintext, combined + ENC_NONCE_BYTES,
                                 ciphertext_len, combined, vault_key) != 0) {
    free(combined);
    free(plaintext);
    return -1;
  }
  plaintext[plaintext_len] = '\0';
  *out = (char *)plaintext;

  free(combined);
  return 0;
}
