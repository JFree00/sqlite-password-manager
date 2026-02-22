#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/database.h"
#include "../include/encryption.h"

typedef struct {
  int argc;
  int length;
  int min_length;
} read_data;

void onClose() {}
int AddEntry(sqlite3 *db, char **err) {
  char hash[crypto_pwhash_STRBYTES];

  char password[100];
  secure_buf password_buf = {0};
  if (secure_buf_lock(&password_buf, password, sizeof(password)) != 0) {
    return -1;
  }
  puts("Enter Password");
  if (scanf("%99s", password) != 1) {
    secure_buf_unlock(&password_buf);
    return -1;
  }

  if (hash_secure(&password_buf, hash) != 0) {
    secure_buf_unlock(&password_buf);
    return -1;
  }
  if (secure_buf_unlock(&password_buf) != 0) {
    return -1;
  }
  char entry_name[100];
  char username[100];
  puts("enter the entry name");
  if (scanf("%99s", entry_name) != 1) {
    return -1;
  }
  puts("enter the username");
  if (scanf("%99s", username) != 1) {
    return -1;
  }
  int res = create_entry(db, entry_name, username, hash);
  if (res != SQLITE_DONE) {
    puts(sqlite3_errstr(res));
    return -1;
  }
  return 0;
}

int SetupMasterKey(sqlite3 *db) {
  bool has_master_key = false;
  if (master_key_exists(db, &has_master_key) != SQLITE_OK) {
    return -1;
  }

  char master_key[100];
  secure_buf master_key_buf = {0};
  if (secure_buf_lock(&master_key_buf, master_key, sizeof(master_key)) != 0) {
    return -1;
  }

  if (!has_master_key) {
    char master_key_hash[crypto_pwhash_STRBYTES];
    puts("No master key found. Create a master key");
    if (scanf("%99s", master_key) != 1) {
      secure_buf_unlock(&master_key_buf);
      return -1;
    }
    if (hash_secure(&master_key_buf, master_key_hash) != 0) {
      secure_buf_unlock(&master_key_buf);
      return -1;
    }
    if (secure_buf_unlock(&master_key_buf) != 0) {
      return -1;
    }
    int set_res = set_master_key(db, master_key_hash);
    if (set_res != SQLITE_DONE && set_res != SQLITE_OK) {
      return -1;
    }
    return 0;
  }

  puts("Enter master key");
  if (scanf("%99s", master_key) != 1) {
    secure_buf_unlock(&master_key_buf);
    return -1;
  }
  const int verify_res = verify_master_key(db, master_key);
  if (secure_buf_unlock(&master_key_buf) != 0) {
    return -1;
  }
  if (verify_res != SQLITE_OK) {
    puts("Invalid master key");
    return -1;
  }
  return 0;
}
int DisplayEntry(void *ctx, int argc, char **value, char **name) {
  read_data *index = (read_data *)ctx;
  if (index->argc == 0) {
    int username_index = -1;
    // get longest value
    for (int i = 0; i < argc; i++) {
      if (name[i] && strcmp(name[i], "username") == 0) {
        username_index = i;
      }
      if (value[i] && name[i] && strlen(value[i]) > index->length) {
        index->length = strlen(value[i]);
      }
    }
    if (index->min_length > index->length) {
      index->length = index->min_length;
    }
    if ((int)strlen("password") > index->length) {
      index->length = (int)strlen("password");
    }
    if ((int)strlen("****") > index->length) {
      index->length = (int)strlen("****");
    }
    // columns
    for (int i = 0; i < argc; i++) {
      printf("%-*s  ", (int)index->length, name[i]);
      if (i == username_index) {
        printf("%-*s  ", (int)index->length, "password");
      }
    }
    if (username_index == -1) {
      printf("%-*s  ", (int)index->length, "password");
    }
    puts("");
  }

  // values
  int username_index = -1;
  for (int i = 0; i < argc; i++) {
    if (name[i] && strcmp(name[i], "username") == 0) {
      username_index = i;
      break;
    }
  }
  for (int i = 0; i < argc; i++) {
    printf("%-*s  ", (int)index->length, value[i] ? value[i] : "NULL");
    if (i == username_index) {
      printf("%-*s  ", (int)index->length, "****");
    }
  }
  if (username_index == -1) {
    printf("%-*s  ", (int)index->length, "****");
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
  if (SetupMasterKey(db) != 0) {
    fprintf(stderr, "Failed to authenticate master key\n");
    db_close(db);
    return EXIT_FAILURE;
  }
  puts("1 to display entries. 2 to add to db\n");
  int CHOICE = 0;
  if (scanf("%d", &CHOICE) != 1) {
    CHOICE = 0;
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
