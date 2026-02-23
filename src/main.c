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
  const unsigned char *vault_key;
  size_t vault_key_len;
} read_data;

void onClose() {}

/* Prompts for entry fields and stores a fully encrypted row using session
 * vault key. */
int AddEntry(sqlite3 *db, const unsigned char *vault_key, size_t vault_key_len,
             char **err) {
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
  int res =
      create_entry(db, entry_name, username, hash, vault_key, vault_key_len);
  if (res != SQLITE_DONE) {
    puts(sqlite3_errstr(res));
    return -1;
  }
  return 0;
}

/* First run: stores master auth hash and wrapped random vault key.
 * Existing setup: verifies master password and unwraps vault key for session.
 */
int SetupMasterKey(sqlite3 *db, secure_buf *master_key_buf,
                   unsigned char *vault_key_out, size_t vault_key_out_len) {
  bool has_master_key = false;
  if (master_key_exists(db, &has_master_key) != SQLITE_OK) {
    return -1;
  }

  if (!master_key_buf || master_key_buf->magic != SECURE_BUF_MAGIC ||
      !master_key_buf->buf || master_key_buf->len == 0 || !vault_key_out ||
      vault_key_out_len != crypto_secretbox_KEYBYTES) {
    return -1;
  }

  if (!has_master_key) {
    // First run path: collect master password and setup vault key material.
    char master_key_confirm[100] = {0};
    secure_buf master_key_confirm_buf = {0};
    char master_key_hash[crypto_pwhash_STRBYTES];
    unsigned char kdf_salt[crypto_pwhash_SALTBYTES] = {0};
    unsigned char wrapping_key[crypto_secretbox_KEYBYTES] = {0};
    char *vault_key_wrapped = nullptr;
    char *vault_key_plain = nullptr;
    size_t vault_key_plain_len = 0;

    if (secure_buf_lock(&master_key_confirm_buf, master_key_confirm,
                        sizeof(master_key_confirm)) != 0) {
      return -1;
    }
    puts("No master key found. Create a master key");
    if (scanf("%99s", master_key_buf->buf) != 1) {
      secure_buf_unlock(&master_key_confirm_buf);
      return -1;
    }
    puts("Re-enter master key");
    if (scanf("%99s", master_key_confirm_buf.buf) != 1) {
      secure_buf_unlock(&master_key_confirm_buf);
      return -1;
    }
    if (strcmp(master_key_buf->buf, master_key_confirm_buf.buf) != 0) {
      puts("Master keys do not match");
      secure_buf_unlock(&master_key_confirm_buf);
      return -1;
    }
    if (secure_buf_unlock(&master_key_confirm_buf) != 0) {
      return -1;
    }
    if (hash_secure(master_key_buf, master_key_hash) != 0) {
      return -1;
    }

    // Generate per-install salt, then derive unwrap key from master password.
    randombytes_buf(kdf_salt, sizeof(kdf_salt));
    if (derive_wrapping_key(master_key_buf->buf, kdf_salt, sizeof(kdf_salt),
                            wrapping_key) != 0) {
      return -1;
    }

    // Create random vault key used for all entry encryption this session.
    randombytes_buf(vault_key_out, vault_key_out_len);
    vault_key_plain_len = sodium_base64_ENCODED_LEN(
        vault_key_out_len, sodium_base64_VARIANT_ORIGINAL);
    vault_key_plain = (char *)malloc(vault_key_plain_len);
    if (!vault_key_plain) {
      sodium_memzero(wrapping_key, sizeof(wrapping_key));
      return -1;
    }
    sodium_bin2base64(vault_key_plain, vault_key_plain_len, vault_key_out,
                      vault_key_out_len, sodium_base64_VARIANT_ORIGINAL);

    if (encrypt_with_vault_key(vault_key_plain, wrapping_key,
                               sizeof(wrapping_key),
                               &vault_key_wrapped) != 0) {
      free(vault_key_plain);
      sodium_memzero(wrapping_key, sizeof(wrapping_key));
      return -1;
    }

    // Persist auth hash + salt + wrapped vault key as the single source of truth.
    int set_res =
        set_master_key_material(db, master_key_hash, kdf_salt, sizeof(kdf_salt),
                                vault_key_wrapped);
    free(vault_key_plain);
    free(vault_key_wrapped);
    sodium_memzero(wrapping_key, sizeof(wrapping_key));
    if (set_res != SQLITE_DONE && set_res != SQLITE_OK) {
      return -1;
    }
    return 0;
  }

  unsigned char kdf_salt[crypto_pwhash_SALTBYTES] = {0};
  unsigned char wrapping_key[crypto_secretbox_KEYBYTES] = {0};
  char *vault_key_wrapped = nullptr;
  char *vault_key_plain = nullptr;
  size_t decoded_len = 0;

  // Normal login path: verify password, then unwrap existing vault key.
  puts("Enter master key");
  if (scanf("%99s", master_key_buf->buf) != 1) {
    return -1;
  }
  const int verify_res = verify_master_key(db, master_key_buf->buf);
  if (verify_res != SQLITE_OK) {
    puts("Invalid master key");
    return -1;
  }
  if (get_master_key_material(db, kdf_salt, sizeof(kdf_salt),
                              &vault_key_wrapped) != SQLITE_OK) {
    return -1;
  }
  if (derive_wrapping_key(master_key_buf->buf, kdf_salt, sizeof(kdf_salt),
                          wrapping_key) != 0) {
    free(vault_key_wrapped);
    return -1;
  }
  if (decrypt_with_vault_key(vault_key_wrapped, wrapping_key,
                             sizeof(wrapping_key), &vault_key_plain) != 0) {
    free(vault_key_wrapped);
    sodium_memzero(wrapping_key, sizeof(wrapping_key));
    return -1;
  }
  // Convert stored base64 vault key back to raw bytes for runtime use.
  if (sodium_base642bin(vault_key_out, vault_key_out_len, vault_key_plain,
                        strlen(vault_key_plain), nullptr, &decoded_len, nullptr,
                        sodium_base64_VARIANT_ORIGINAL) != 0 ||
      decoded_len != vault_key_out_len) {
    free(vault_key_wrapped);
    free(vault_key_plain);
    sodium_memzero(wrapping_key, sizeof(wrapping_key));
    return -1;
  }
  free(vault_key_wrapped);
  free(vault_key_plain);
  sodium_memzero(wrapping_key, sizeof(wrapping_key));
  return 0;
}

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
    for (int i = 0; i < argc; i++) {
      char *decrypted_value = nullptr;
      const char *display_value = value[i];
      if (name[i] && strcmp(name[i], "username") == 0) {
        username_index = i;
      }
      // Decrypt only encrypted display columns; leave metadata as-is.
      if (value[i] && should_decrypt_column(name[i]) &&
          is_encrypted_value(value[i])) {
        if (decrypt_with_vault_key(value[i], index->vault_key,
                                   index->vault_key_len,
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
    if (value[i] && should_decrypt_column(name[i]) &&
        is_encrypted_value(value[i])) {
      if (decrypt_with_vault_key(value[i], index->vault_key,
                                 index->vault_key_len,
                                 &decrypted_value) == 0) {
        display_value = decrypted_value;
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

int GetEntries(sqlite3 *db, const unsigned char *vault_key, size_t vault_key_len,
               char **err) {
  read_data data = {0, 0, 10, vault_key, vault_key_len};
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
  unsigned char session_vault_key[crypto_secretbox_KEYBYTES] = {0};
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
  // Authenticates user and fills session_vault_key for this process lifetime.
  if (SetupMasterKey(db, &master_key_buf, session_vault_key,
                     sizeof(session_vault_key)) != 0) {
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
      res = GetEntries(db, session_vault_key, sizeof(session_vault_key), &err);
      break;
    case 2:
      res = AddEntry(db, session_vault_key, sizeof(session_vault_key), &err);
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
  sodium_memzero(session_vault_key, sizeof(session_vault_key));
  secure_buf_unlock(&master_key_buf);

  return res;
}
