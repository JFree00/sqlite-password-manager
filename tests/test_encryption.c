#include <stdlib.h>

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
  sodium_mlock(password, sizeof(password));
  int res = hash(password, out, crypto_pwhash_STRBYTES);
  TEST_ASSERT_EQUAL(0, res);
}

void test_check_hash_against_password_success() {
  char out[crypto_pwhash_STRBYTES];
  char password[124] = TEST_PASSWORD;
  sodium_mlock(password, sizeof(password));
  hash(password, out, sizeof(password));
  // Password is now empty
  // Re-init
  char copyPassword[124] = TEST_PASSWORD;

  int res = check(copyPassword, out, sizeof(password));
  TEST_ASSERT_EQUAL(0, res);
}
void test_check_hash_against_password_failure() {
  char out[crypto_pwhash_STRBYTES];
  char password[124] = TEST_PASSWORD;
  sodium_mlock(password, sizeof(password));
  hash(password, out, crypto_pwhash_STRBYTES);

  char wrong_password[124] = "WRONG PASSWORD";
  int res = check(wrong_password, out, crypto_pwhash_STRBYTES);
  TEST_ASSERT_NOT_EQUAL(0, res);
}

void test_create_password() {
  char out[crypto_pwhash_STRBYTES];
  char password[124] = TEST_PASSWORD;
  sodium_mlock(password, sizeof(password));
  int res = createPassword(password, out, crypto_pwhash_STRBYTES);
  TEST_ASSERT_EQUAL(0, res);
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
  return UNITY_END();
}
