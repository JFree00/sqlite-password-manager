#pragma once
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

/* Encrypts entry fields with a master key (secretbox + random nonce + base64)
 * and inserts into main_table. */
int create_entry(sqlite3 *db, const char *entry_name, const char *username,
                 const char *hash, const char *master_key);

int dehash_entry(sqlite3 *db, char **err);

int GetAllEntries(sqlite3 *db, int (*callback)(void *, int, char **, char **),
                  void *callback_data, char **err);
/* Stores the master-key verifier hash (crypto_pwhash) in the
 * master_key row (id=1). */
int set_master_key(sqlite3 *db, const char *hash);
/* Checks whether a master key row exists (id=1). */
int master_key_exists(sqlite3 *db, bool *exists);
/* Verifies the provided master key against the stored crypto_pwhash hash using
 * crypto_pwhash_str_verify. */
int verify_master_key(sqlite3 *db, const char *master_key);
int db_init(sqlite3 **db, const char *filename, bool readonly);
#endif  // FIRST_C_PROJECT_DATABASE_H
