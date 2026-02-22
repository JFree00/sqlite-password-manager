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
  const char *master_key;
} read_data;

void onClose() {}
int AddEntry(sqlite3 *db, const char *master_key, char **err) {
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
  int res = create_entry(db, entry_name, username, hash, master_key);
  if (res != SQLITE_DONE) {
    puts(sqlite3_errstr(res));
    return -1;
  }
  return 0;
}

/* First run: creates and stores master-key verifier hash.
 * Subsequent runs: verifies provided plaintext master key against stored hash.
 */
int SetupMasterKey(sqlite3 *db, secure_buf *master_key_buf) {
  bool has_master_key = false;
  if (master_key_exists(db, &has_master_key) != SQLITE_OK) {
    return -1;
  }

  if (!master_key_buf || master_key_buf->magic != SECURE_BUF_MAGIC ||
      !master_key_buf->buf || master_key_buf->len == 0) {
    return -1;
  }

  if (!has_master_key) {
    char master_key_hash[crypto_pwhash_STRBYTES];
    puts("No master key found. Create a master key");
    if (scanf("%99s", master_key_buf->buf) != 1) {
      return -1;
    }
    if (hash_secure(master_key_buf, master_key_hash) != 0) {
      return -1;
    }
    int set_res = set_master_key(db, master_key_hash);
    if (set_res != SQLITE_DONE && set_res != SQLITE_OK) {
      return -1;
    }
    return 0;
  }

  puts("Enter master key");
  if (scanf("%99s", master_key_buf->buf) != 1) {
    return -1;
  }
  const int verify_res = verify_master_key(db, master_key_buf->buf);
  if (verify_res != SQLITE_OK) {
    puts("Invalid master key");
    return -1;
  }
  return 0;
}

/* Decrypt only columns that are stored encrypted at rest. */
static int should_decrypt_column(const char *column_name) {
  if (!column_name) {
    return 0;
  }
  return strcmp(column_name, "entry_name") == 0 ||
         strcmp(column_name, "username") == 0;
}

int DisplayEntry(void *ctx, int argc, char **value, char **name) {
  read_data *index = (read_data *)ctx;
  if (index->argc == 0) {
    int username_index = -1;
    // get longest value
    for (int i = 0; i < argc; i++) {
      char *decrypted_value = nullptr;
      const char *display_value = value[i];
      if (name[i] && strcmp(name[i], "username") == 0) {
        username_index = i;
      }
      if (value[i] && should_decrypt_column(name[i])) {
        if (decrypt_with_master_key(value[i], index->master_key,
                                    &decrypted_value) == 0) {
          display_value = decrypted_value;
        }
      }
      if (display_value && name[i] &&
          (int)strlen(display_value) > index->length) {
        index->length = (int)strlen(display_value);
      }
      free(decrypted_value);
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
    char *decrypted_value = nullptr;
    const char *display_value = value[i] ? value[i] : "NULL";
    if (value[i] && should_decrypt_column(name[i])) {
      if (decrypt_with_master_key(value[i], index->master_key,
                                  &decrypted_value) == 0) {
        display_value = decrypted_value;
      } else {
        display_value = "<decrypt-failed>";
      }
    }
    printf("%-*s  ", (int)index->length, display_value);
    if (i == username_index) {
      printf("%-*s  ", (int)index->length, "****");
    }
    free(decrypted_value);
  }
  if (username_index == -1) {
    printf("%-*s  ", (int)index->length, "****");
  }
  puts("");
  *(int *)index += 1;
  return 0;
}
/* Loads rows and decrypts encrypted display columns with session master key. */
int GetEntries(sqlite3 *db, const char *master_key, char **err) {
  read_data data = {0, 0, 10, master_key};
  return GetAllEntries(db, DisplayEntry, &data, err);
}

int main(void) {
  atexit(onClose);
  sqlite3 *db = nullptr;
  if (sodium_init() < 0) {
    exit(EXIT_FAILURE);
  };
  char *err = nullptr;
  char master_key[100] = {0};
  secure_buf master_key_buf = {0};
  if (secure_buf_lock(&master_key_buf, master_key, sizeof(master_key)) != 0) {
    fprintf(stderr, "Failed to initialize secure master key buffer\n");
    return EXIT_FAILURE;
  }
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
    secure_buf_unlock(&master_key_buf);
    return EXIT_FAILURE;
  }
  if (SetupMasterKey(db, &master_key_buf) != 0) {
    fprintf(stderr, "Failed to authenticate master key\n");
    db_close(db);
    secure_buf_unlock(&master_key_buf);
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
      res = GetEntries(db, master_key_buf.buf, &err);
      break;
    case 2:
      res = AddEntry(db, master_key_buf.buf, &err);
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
  secure_buf_unlock(&master_key_buf);

  return res;
}
