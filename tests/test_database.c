
#include <assert.h>
#include <sodium/crypto_pwhash.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/database.h"
#include "../include/encryption.h"
#include "unity/unity.h"

#define TEST_ENTRY_NAME "test_entry_name"
#define TEST_USERNAME "test_username"
#define TEST_PASSWORD "test_password"
#define TEST_MASTER_KEY "master-key"

static const unsigned char TEST_VAULT_KEY[crypto_secretbox_KEYBYTES] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
    0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20};

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
  char hash[crypto_pwhash_STRBYTES] = {0};
  char *err = nullptr;
  TEST_ASSERT_EQUAL_INT(0, createPassword(TEST_PASSWORD, hash));
  int create_res = create_entry(db, TEST_ENTRY_NAME, TEST_USERNAME, hash,
                                TEST_VAULT_KEY, sizeof(TEST_VAULT_KEY));
  TEST_ASSERT_EQUAL_INT(SQLITE_DONE, create_res);
  int res = db_execute(db, SELECT_ALL, nullptr, nullptr, &err);
  if (err) {
    printf("SQLite error: %s\n", err);
    sqlite3_free(err);
  }
  TEST_ASSERT_EQUAL_INT(res, SQLITE_OK);
}
void test_create_entry_failure(void) {
  char hash[crypto_pwhash_STRBYTES] = {0};
  int create_res = create_entry(nullptr, TEST_ENTRY_NAME, TEST_USERNAME, hash,
                                TEST_VAULT_KEY, sizeof(TEST_VAULT_KEY));
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
  unsigned char salt[crypto_pwhash_SALTBYTES] = {0};
  unsigned char loaded_salt[crypto_pwhash_SALTBYTES] = {0};
  char *wrapped_vault_key = nullptr;
  char *loaded_wrapped_vault_key = nullptr;

  int exists_res = master_key_exists(db, &exists);
  TEST_ASSERT_EQUAL_INT(SQLITE_OK, exists_res);
  TEST_ASSERT_FALSE(exists);

  TEST_ASSERT_EQUAL_INT(0, createPassword(TEST_PASSWORD, hash_value));
  randombytes_buf(salt, sizeof(salt));
  TEST_ASSERT_EQUAL(0, encrypt_with_vault_key("vault-key-material",
                                               TEST_VAULT_KEY,
                                               sizeof(TEST_VAULT_KEY),
                                               &wrapped_vault_key));

  int set_res = set_master_key_material(db, hash_value, salt, sizeof(salt),
                                        wrapped_vault_key);
  TEST_ASSERT_TRUE(set_res == SQLITE_DONE || set_res == SQLITE_OK);

  exists_res = master_key_exists(db, &exists);
  TEST_ASSERT_EQUAL_INT(SQLITE_OK, exists_res);
  TEST_ASSERT_TRUE(exists);

  int verify_res = verify_master_key(db, TEST_PASSWORD);
  TEST_ASSERT_EQUAL_INT(SQLITE_OK, verify_res);

  verify_res = verify_master_key(db, "wrong-password");
  TEST_ASSERT_EQUAL_INT(SQLITE_AUTH, verify_res);

  TEST_ASSERT_EQUAL_INT(SQLITE_OK, get_master_key_material(db, loaded_salt,
                                                           sizeof(loaded_salt),
                                                           &loaded_wrapped_vault_key));
  TEST_ASSERT_EQUAL_INT(0, memcmp(salt, loaded_salt, sizeof(salt)));
  TEST_ASSERT_EQUAL_STRING(wrapped_vault_key, loaded_wrapped_vault_key);

  free(wrapped_vault_key);
  free(loaded_wrapped_vault_key);
}

void test_create_entry_stores_encrypted_values(void) {
  char hash[crypto_pwhash_STRBYTES] = {0};
  sqlite3_stmt *stmt = nullptr;

  TEST_ASSERT_EQUAL_INT(0, createPassword(TEST_PASSWORD, hash));
  TEST_ASSERT_EQUAL_INT(SQLITE_DONE,
                        create_entry(db, TEST_ENTRY_NAME, TEST_USERNAME, hash,
                                     TEST_VAULT_KEY, sizeof(TEST_VAULT_KEY)));

  TEST_ASSERT_EQUAL_INT(
      SQLITE_OK,
      sqlite3_prepare_v2(db, "select entry_name, username from main_table limit 1",
                         -1, &stmt, nullptr));
  TEST_ASSERT_EQUAL_INT(SQLITE_ROW, sqlite3_step(stmt));

  const char *stored_entry_name = (const char *)sqlite3_column_text(stmt, 0);
  const char *stored_username = (const char *)sqlite3_column_text(stmt, 1);

  TEST_ASSERT_NOT_NULL(stored_entry_name);
  TEST_ASSERT_NOT_NULL(stored_username);
  TEST_ASSERT_NOT_EQUAL(0, strcmp(stored_entry_name, TEST_ENTRY_NAME));
  TEST_ASSERT_NOT_EQUAL(0, strcmp(stored_username, TEST_USERNAME));

  sqlite3_finalize(stmt);
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
  RUN_TEST(test_create_entry_stores_encrypted_values);
  if (db != nullptr) db_close(db);
  return UNITY_END();
}
