
#include <assert.h>
#include <sodium/crypto_pwhash.h>
#include <stdio.h>

#include "../include/database.h"
#include "unity/unity.h"

#define TEST_ENTRY_NAME "test_entry_name"
#define TEST_USERNAME "test_username"
#define TEST_PASSWORD "test_password"

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
int main() {
  UNITY_BEGIN();
  RUN_TEST(test_create_entry_success);
  RUN_TEST(test_create_entry_failure);
  RUN_TEST(test_get_all_entries);
  RUN_TEST(test_db_init_open_failure);
  RUN_TEST(test_db_init_template_failure);
  if (db != nullptr) db_close(db);
  return UNITY_END();
}
