#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/database.h"
#include "../include/encryption.h"
#include "../include/sqlite3.h"

typedef struct {
  int argc;
  int length;
  int min_length;
} read_data;

void onClose() {}
int AddEntry(sqlite3 *db, char **err) {
  char hash[crypto_pwhash_STRBYTES];

  char password[100];
  puts("Enter Password");
  scanf("%s", password);

  if (createPassword(password, hash) != 0) {
    return -1;
  }
  char entry_name[100];
  char username[100];
  puts("enter the entry name");
  scanf("%s", entry_name);
  puts("enter the username");
  scanf("%s", username);
  int res = create_entry(db, entry_name, username, hash);
  if (res != SQLITE_DONE) {
    puts(sqlite3_errstr(res));
    return -1;
  }
  return 0;
}
int DisplayEntry(void *ctx, int argc, char **value, char **name) {
  read_data *index = (read_data *)ctx;
  if (index->argc == 0) {
    // get longest value
    for (int i = 0; i < argc; i++) {
      if (value[i] && name[i] && strlen(value[i]) > index->length) {
        if (strcmp(name[i], "hash") == 0) {
          continue;
        }
        index->length = strlen(value[i]);
      }
    }
    // columns
    for (int i = 0; i < argc; i++) {
      printf("%-*s  ", (int)index->length, name[i]);
    }
    puts("");
  }

  // values
  for (int i = 0; i < argc; i++) {
    // TODO: stop retrieving hashes
    if (strcmp(name[i], "hash") == 0) {
      printf("%-*s  ", (int)index->length, "****");
      continue;
    }
    printf("%-*s  ", (int)index->length, value[i] ? value[i] : "NULL");
  }
  puts("");
  *(int *)index += 1;
  return 0;
}
int GetEntries(sqlite3 *db, char **err) {
  read_data data = {0, 0, 10};
  return GetAllEntries(db, DisplayEntry, &data, err);
}

int main(void) {
  atexit(onClose);
  sqlite3 *db = nullptr;
  if (sodium_init() < 0) {
    exit(EXIT_FAILURE);
  };
  char *err = nullptr;
  const int init_db = db_init(&db, DB_NAME, false);
  if (init_db != 0) {
    switch (init_db) {
      default:
      case 1:
        puts("db could not open\n");
        break;
      case 2:
        puts("db could not create table\n");
        break;
    }
    fprintf(stderr, "Failed to initialize database\n");
    return EXIT_FAILURE;
  }
  puts("1 to display entries. 2 to add to db\n");
  char input[64];
  int CHOICE = 0;
  if (fgets(input, sizeof(input), stdin)) {
    CHOICE = (int)strtol(input, nullptr, 10);
  }
  int res = 0;
  switch (CHOICE) {
    case 1:
    default:
      res = GetEntries(db, &err);
      break;
    case 2:
      res = AddEntry(db, &err);
      break;
  }
  fflush(stdout);
  if (res != SQLITE_OK) {
    if (db) {
      fprintf(stderr, "SQLite error: %s\n", sqlite3_errmsg(db));
    }
    if (err) {
      fprintf(stderr, "Error message: %s\n", err);
      sqlite3_free(err);
    }
  }

  if (db) {
    db_close(db);
  }

  return res;
}
