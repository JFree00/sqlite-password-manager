#ifndef FIRST_C_PROJECT_DATABASE_H
#define FIRST_C_PROJECT_DATABASE_H
#include "sqlite3.h"

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

#define SELECT_ALL "select * from main_table;"
int db_open(const char *filename, sqlite3 **out, int flags);

int db_close(sqlite3 *filename);

int db_execute(sqlite3 *filename, const char *sql,
               int (*callback)(void *, int, char **, char **),
               void *callback_data, char **err);

int db_write(sqlite3 *filename, const char *sql, char **err);

int db_read(sqlite3 *db, const char *sql,
            int (*callback)(void *, int, char **, char **), void *callback_data,
            char **err);

int create_entry(sqlite3 *db, const char *entry_name, const char *username,
                 const char *hash);

int dehash_entry(sqlite3 *db, char **err);

int GetAllEntries(sqlite3 *db, int (*callback)(void *, int, char **, char **),
                  void *callback_data, char **err);
int db_init(sqlite3 **db, const char *filename, bool readonly);
#endif  // FIRST_C_PROJECT_DATABASE_H
