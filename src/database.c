#include "../include/database.h"
#include "../include/encryption.h"

#include <stdio.h>

int db_close(sqlite3 *filename) { return sqlite3_close(filename); }

/* Docs:
*      Restrictions:
The application must ensure that the 1st parameter to sqlite3_exec() is a valid
and open database connection. The application must not close the database
connection specified by the 1st parameter to sqlite3_exec() while sqlite3_exec()
is running. The application must not modify the SQL statement text passed into
the 2nd parameter of sqlite3_exec() while sqlite3_exec() is running. The
application must not dereference the arrays or string pointers passed as the 3rd
and 4th callback parameters after it returns.

todo: Implement 3 separate handlers to ensure these are followed.
*/

int db_execute(sqlite3 *filename, const char *sql,
               int (*callback)(void *, int, char **, char **),
               void *callback_data, char **err) {
  return sqlite3_exec(filename, sql, callback, callback_data, err);
}

int db_write(sqlite3 *filename, const char *sql, char **err) {
  return db_execute(filename, sql, nullptr, nullptr, err);
}

int db_open(const char *filename, sqlite3 **out, const int flags) {
  int res = sqlite3_open_v2(filename, out, flags, nullptr);
  if (res) return res;
  return 0;
}

int db_read(sqlite3 *db, const char *sql,
            int (*callback)(void *, int, char **, char **), void *callback_data,
            char **err) {
  return db_execute(db, sql, callback, callback_data, err);
}
int db_init(sqlite3 **db, const char *filename, bool readonly) {
  char *err = nullptr;
  int flags = readonly ? SQLITE_OPEN_READONLY
                       : (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);

  if (db_open(filename, db, flags) != SQLITE_OK) {
    if (db && *db) {
      db_close(*db);
      *db = nullptr;
    }
    return 1;
  }

#if RELEASE
  if (readonly) return 0;
#endif

  if (db_write(*db, CREATE_TABLE, &err) != SQLITE_OK) {
    if (err) {
      printf("SQLite error: %s\n", err);
      sqlite3_free(err);
    }
    db_close(*db);
    *db = nullptr;
    return 2;
  }
  if (db_write(*db, CREATE_MASTER_KEY_TABLE, &err) != SQLITE_OK) {
    if (err) {
      printf("SQLite error: %s\n", err);
      sqlite3_free(err);
    }
    db_close(*db);
    *db = nullptr;
    return 2;
  }
  return 0;
}

int create_entry(sqlite3 *db, const char *entry_name, const char *username,
                 const char *hash) {
  const char *sql =
      "insert into main_table (entry_name, username, hash) values (?, ?, ?)";
  sqlite3_stmt *stmt;

  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    return -1;
  }
  sqlite3_bind_text(stmt, 1, entry_name, -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 2, username, -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 3, hash, -1, SQLITE_STATIC);
  const int res = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  return res;
}
int dehash_entry(sqlite3 *db, char **err) { return 0; }

int GetAllEntries(sqlite3 *db, int (*callback)(void *, int, char **, char **),
                  void *callback_data, char **err) {
  return db_read(db, SELECT_ALL, callback, callback_data, err);
}

int set_master_key(sqlite3 *db, const char *hash) {
  const char *sql =
      "insert into master_key (id, hash) values (1, ?) "
      "on conflict(id) do update set hash = excluded.hash, "
      "modified_at = CURRENT_TIMESTAMP";
  sqlite3_stmt *stmt = nullptr;

  if (!db || !hash) {
    return SQLITE_MISUSE;
  }
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    return SQLITE_ERROR;
  }
  sqlite3_bind_text(stmt, 1, hash, -1, SQLITE_STATIC);
  const int res = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  return res;
}

int master_key_exists(sqlite3 *db, bool *exists) {
  const char *sql = "select 1 from master_key where id = 1 limit 1";
  sqlite3_stmt *stmt = nullptr;

  if (!db || !exists) {
    return SQLITE_MISUSE;
  }
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    return SQLITE_ERROR;
  }
  int step_res = sqlite3_step(stmt);
  if (step_res == SQLITE_ROW) {
    *exists = true;
    sqlite3_finalize(stmt);
    return SQLITE_OK;
  }
  if (step_res == SQLITE_DONE) {
    *exists = false;
    sqlite3_finalize(stmt);
    return SQLITE_OK;
  }

  sqlite3_finalize(stmt);
  return step_res;
}

int verify_master_key(sqlite3 *db, const char *master_key) {
  const char *sql = "select hash from master_key where id = 1 limit 1";
  sqlite3_stmt *stmt = nullptr;

  if (!db || !master_key) {
    return SQLITE_MISUSE;
  }
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    return SQLITE_ERROR;
  }

  const int step_res = sqlite3_step(stmt);
  if (step_res != SQLITE_ROW) {
    sqlite3_finalize(stmt);
    if (step_res == SQLITE_DONE) {
      return SQLITE_NOTFOUND;
    }
    return step_res;
  }

  const unsigned char *hash_value = sqlite3_column_text(stmt, 0);
  int is_valid = 0;
  if (hash_value) {
    is_valid = (check(master_key, (const char *)hash_value) == 0);
  }
  sqlite3_finalize(stmt);
  return is_valid ? SQLITE_OK : SQLITE_AUTH;
}
