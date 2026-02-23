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
/* Returns 1 when value matches the encrypted storage format prefix ("v1:"). */
int is_encrypted_value(const char *value);
/* Derives the temporary unwrap key from master password + salt using
 * crypto_pwhash (Argon2id). */
int derive_wrapping_key(const char *master_key, const unsigned char *salt,
                        size_t salt_len,
                        unsigned char out_key[crypto_secretbox_KEYBYTES]);
/* Encrypts text with vault key using secretbox and returns a storable
 * "v1:"+base64 payload. */
int encrypt_with_vault_key(const char *plaintext, const unsigned char *vault_key,
                           size_t vault_key_len, char **out);
/* Decrypts a "v1:"+base64 payload with the vault key. */
int decrypt_with_vault_key(const char *encoded, const unsigned char *vault_key,
                           size_t vault_key_len, char **out);

#endif  // FIRST_C_PROJECT_ENCRYPTION_H
