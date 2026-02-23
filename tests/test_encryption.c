#include <stdlib.h>
#include <string.h>

#include "../include/encryption.h"
#include "unity/unity.h"

#define TEST_PASSWORD "test_password"
void setUp(void) {}

void tearDown(void) {}

static void enable_fast_pwhash_for_tests(void) {
#ifdef _WIN32
  _putenv("PWHASH_FAST=1");
#else
  setenv("PWHASH_FAST", "1", 1);
#endif
}

void test_hash() {
  char out[crypto_pwhash_STRBYTES];
  char password[124] = TEST_PASSWORD;
  secure_buf password_buf = {0};
  TEST_ASSERT_EQUAL(0, secure_buf_lock(&password_buf, password, sizeof(password)));
  int res = hash_secure(&password_buf, out);
  TEST_ASSERT_EQUAL(0, secure_buf_unlock(&password_buf));
  TEST_ASSERT_EQUAL(0, res);
}

void test_check_hash_against_password_success() {
  char out[crypto_pwhash_STRBYTES];
  char password[124] = TEST_PASSWORD;
  secure_buf password_buf = {0};
  TEST_ASSERT_EQUAL(0, secure_buf_lock(&password_buf, password, sizeof(password)));
  hash_secure(&password_buf, out);
  TEST_ASSERT_EQUAL(0, secure_buf_unlock(&password_buf));

  char copyPassword[124] = TEST_PASSWORD;
  secure_buf copy_buf = {0};
  TEST_ASSERT_EQUAL(0, secure_buf_lock(&copy_buf, copyPassword, sizeof(copyPassword)));
  int res = check_secure(&copy_buf, out);
  TEST_ASSERT_EQUAL(0, secure_buf_unlock(&copy_buf));
  TEST_ASSERT_EQUAL(0, res);
}
void test_check_hash_against_password_failure() {
  char out[crypto_pwhash_STRBYTES];
  char password[124] = TEST_PASSWORD;
  secure_buf password_buf = {0};
  TEST_ASSERT_EQUAL(0, secure_buf_lock(&password_buf, password, sizeof(password)));
  hash_secure(&password_buf, out);
  TEST_ASSERT_EQUAL(0, secure_buf_unlock(&password_buf));

  char wrong_password[124] = "WRONG PASSWORD";
  secure_buf wrong_buf = {0};
  TEST_ASSERT_EQUAL(0, secure_buf_lock(&wrong_buf, wrong_password, sizeof(wrong_password)));
  int res = check_secure(&wrong_buf, out);
  TEST_ASSERT_EQUAL(0, secure_buf_unlock(&wrong_buf));
  TEST_ASSERT_NOT_EQUAL(0, res);
}

void test_create_password() {
  char out[crypto_pwhash_STRBYTES];
  int res = createPassword(TEST_PASSWORD, out);
  TEST_ASSERT_EQUAL(0, res);
}

void test_encrypt_decrypt_with_vault_key() {
  const char *plaintext = "entry-value";
  const unsigned char vault_key[crypto_secretbox_KEYBYTES] = {
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
      0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
      0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F};
  char *ciphertext = nullptr;
  char *decrypted = nullptr;

  TEST_ASSERT_EQUAL(0, encrypt_with_vault_key(plaintext, vault_key,
                                              sizeof(vault_key), &ciphertext));
  TEST_ASSERT_NOT_NULL(ciphertext);
  TEST_ASSERT_NOT_EQUAL(0, strcmp(ciphertext, plaintext));
  TEST_ASSERT_EQUAL(1, is_encrypted_value(ciphertext));

  TEST_ASSERT_EQUAL(0, decrypt_with_vault_key(ciphertext, vault_key,
                                              sizeof(vault_key), &decrypted));
  TEST_ASSERT_NOT_NULL(decrypted);
  TEST_ASSERT_EQUAL_STRING(plaintext, decrypted);

  free(ciphertext);
  free(decrypted);
}

void test_derive_wrapping_key() {
  const unsigned char salt[crypto_pwhash_SALTBYTES] = {
      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5};
  unsigned char key_a[crypto_secretbox_KEYBYTES] = {0};
  unsigned char key_b[crypto_secretbox_KEYBYTES] = {0};

  TEST_ASSERT_EQUAL(0,
                    derive_wrapping_key("master-key", salt, sizeof(salt), key_a));
  TEST_ASSERT_EQUAL(0,
                    derive_wrapping_key("master-key", salt, sizeof(salt), key_b));
  TEST_ASSERT_EQUAL_INT(0, memcmp(key_a, key_b, sizeof(key_a)));
}

int main() {
  if (sodium_init() < 0) {
    exit(EXIT_FAILURE);
  };
  enable_fast_pwhash_for_tests();
  UNITY_BEGIN();
  RUN_TEST(test_hash);
  RUN_TEST(test_check_hash_against_password_success);
  RUN_TEST(test_check_hash_against_password_failure);
  RUN_TEST(test_create_password);
  RUN_TEST(test_encrypt_decrypt_with_vault_key);
  RUN_TEST(test_derive_wrapping_key);
  return UNITY_END();
}
