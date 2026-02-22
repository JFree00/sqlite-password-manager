
#include <assert.h>
#include <sodium/crypto_pwhash.h>
#include <stdio.h>
#include <stdlib.h>

#include "../include/database.h"
#include "../include/encryption.h"
#include "unity/unity.h"

#define TEST_ENTRY_NAME "test_entry_name"
#define TEST_USERNAME "test_username"
#define TEST_PASSWORD "test_password"

static void enable_fast_pwhash_for_tests(void) {
#ifdef _WIN32
  _putenv("PWHASH_FAST=1");
#else
  setenv("PWHASH_FAST", "1", 1);
#endif
}

sqlite3 *db = nullptr;

void setUp(void) {
  int init_res = db_init(&db, ":memory:", false);
  TEST_ASSERT_EQUAL_INT(init_res, 0);
}

void tearDown(void) {
  if (db != nullptr) {
    db_close(db);
    db = nullptr;
  }
}

void test_create_entry_success(void) {
  char hash[crypto_pwhash_STRBYTES];
  char *err = nullptr;
  int create_res = create_entry(db, TEST_ENTRY_NAME, TEST_USERNAME, hash);
  int res = db_execute(db, SELECT_ALL, nullptr, nullptr, &err);
  if (err) {
    printf("SQLite error: %s\n", err);
    sqlite3_free(err);
  }
  TEST_ASSERT_EQUAL_INT(res, SQLITE_OK);
}
void test_create_entry_failure(void) {
  char hash[crypto_pwhash_STRBYTES] = {0};
  int create_res = create_entry(nullptr, TEST_ENTRY_NAME, TEST_USERNAME, hash);
  TEST_ASSERT_NOT_EQUAL(0, create_res);
}
void test_db_init_open_failure(void) {
  sqlite3 *bad_db = nullptr;
  int init_res = db_init(&bad_db, ".", false);
  TEST_ASSERT_NOT_EQUAL(0, init_res);
  if (bad_db) {
    db_close(bad_db);
  }
}
void test_db_init_template_failure(void) {
  sqlite3 *bad_db = nullptr;
  int init_res = db_init(&bad_db, ":memory:", true);
  TEST_ASSERT_NOT_EQUAL(0, init_res);
  if (bad_db) {
    db_close(bad_db);
  }
}

void test_get_all_entries(void) {
  char *err = nullptr;
  int res = GetAllEntries(db, nullptr, nullptr, &err);
  if (err) {
    printf("SQLite error: %s\n", err);
    sqlite3_free(err);
  }
  TEST_ASSERT_EQUAL_INT(res, SQLITE_OK);
}

void test_master_key_lifecycle(void) {
  bool exists = true;
  char hash_value[crypto_pwhash_STRBYTES] = {0};

  int exists_res = master_key_exists(db, &exists);
  TEST_ASSERT_EQUAL_INT(SQLITE_OK, exists_res);
  TEST_ASSERT_FALSE(exists);

  TEST_ASSERT_EQUAL_INT(0, createPassword(TEST_PASSWORD, hash_value));

  int set_res = set_master_key(db, hash_value);
  TEST_ASSERT_TRUE(set_res == SQLITE_DONE || set_res == SQLITE_OK);

  exists_res = master_key_exists(db, &exists);
  TEST_ASSERT_EQUAL_INT(SQLITE_OK, exists_res);
  TEST_ASSERT_TRUE(exists);

  int verify_res = verify_master_key(db, TEST_PASSWORD);
  TEST_ASSERT_EQUAL_INT(SQLITE_OK, verify_res);

  verify_res = verify_master_key(db, "wrong-password");
  TEST_ASSERT_EQUAL_INT(SQLITE_AUTH, verify_res);
}

int main() {
  if (sodium_init() < 0) {
    return 1;
  }
  enable_fast_pwhash_for_tests();

  UNITY_BEGIN();
  RUN_TEST(test_create_entry_success);
  RUN_TEST(test_create_entry_failure);
  RUN_TEST(test_get_all_entries);
  RUN_TEST(test_db_init_open_failure);
  RUN_TEST(test_db_init_template_failure);
  RUN_TEST(test_master_key_lifecycle);
  if (db != nullptr) db_close(db);
  return UNITY_END();
}
