#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <sqlite3.h>
#ifndef FIRST_C_PROJECT_DATABASE_H

#define FIRST_C_PROJECT_DATABASE_H

#define DB_NAME "identifier.sqlite"
#define CREATE_TABLE                                        \
  "create table if not exists main_table "                  \
  "("                                                       \
  "    entry_name TEXT not null "                           \
  "        constraint main_table_pk "                       \
  "            primary key, "                               \
  "    username   TEXT, "                                   \
  "    hash       TEXT not null, "                          \
  "   created_at TEXT default CURRENT_TIMESTAMP not null, " \
  "    modified_at TEXT "                                   \
  ") "                                                      \
  "without rowid;"

#define CREATE_MASTER_KEY_TABLE                             \
  "create table if not exists master_key ("                 \
  "    id INTEGER primary key check (id = 1), "             \
  "    hash TEXT not null, "                                \
  "    kdf_salt BLOB not null, "                            \
  "    vault_key_encrypted TEXT not null, "                 \
  "    created_at TEXT default CURRENT_TIMESTAMP not null, "\
  "    modified_at TEXT"                                    \
  ");"

#define SELECT_ALL \
  "select entry_name, username, created_at, modified_at from main_table;"
int db_open(const char *filename, sqlite3 **out, int flags);

int db_close(sqlite3 *filename);

int db_execute(sqlite3 *filename, const char *sql,
               int (*callback)(void *, int, char **, char **),
               void *callback_data, char **err);

int db_write(sqlite3 *filename, const char *sql, char **err);

int db_read(sqlite3 *db, const char *sql,
            int (*callback)(void *, int, char **, char **), void *callback_data,
            char **err);

/* Encrypts entry fields with a vault key (secretbox + random nonce + base64)
 * and inserts into main_table. */
int create_entry(sqlite3 *db, const char *entry_name, const char *username,
                 const char *hash, const unsigned char *vault_key,
                 size_t vault_key_len);

int dehash_entry(sqlite3 *db, char **err);

int GetAllEntries(sqlite3 *db, int (*callback)(void *, int, char **, char **),
                  void *callback_data, char **err);
/* Stores master auth hash plus KDF salt and wrapped vault key in master_key. */
int set_master_key_material(sqlite3 *db, const char *hash,
                            const unsigned char *kdf_salt,
                            size_t kdf_salt_len,
                            const char *vault_key_encrypted);
/* Checks whether a master key row exists (id=1). */
int master_key_exists(sqlite3 *db, bool *exists);
/* Verifies the provided master key against the stored crypto_pwhash hash using
 * crypto_pwhash_str_verify. */
int verify_master_key(sqlite3 *db, const char *master_key);
/* Loads KDF salt and wrapped vault key from master_key. */
int get_master_key_material(sqlite3 *db, unsigned char *kdf_salt,
                            size_t kdf_salt_len, char **vault_key_encrypted);
int db_init(sqlite3 **db, const char *filename, bool readonly);
#endif  // FIRST_C_PROJECT_DATABASE_H
