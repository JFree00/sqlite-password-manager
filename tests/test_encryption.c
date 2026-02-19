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
  int res = hash(TEST_PASSWORD, out);
  TEST_ASSERT_EQUAL(res, 0);
}

void test_check_hash_against_password_success() {
  char out[crypto_pwhash_STRBYTES];
  hash(TEST_PASSWORD, out);

  int res = check(TEST_PASSWORD, out);
  TEST_ASSERT_EQUAL(res, 0);
}
void test_check_hash_against_password_failure() {
  char out[crypto_pwhash_STRBYTES];
  hash(TEST_PASSWORD, out);

  int res = check("WRONG PASSWORD", out);
  TEST_ASSERT_NOT_EQUAL(res, 0);
}

void test_create_password() {
  char out[crypto_pwhash_STRBYTES];
  int res = createPassword(TEST_PASSWORD, out);
  TEST_ASSERT_EQUAL(res, 0);
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
