#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>

#include "encryption.h"

void onClose() {
}


int createMasterPassword() {
    char hashed_password[crypto_pwhash_STRBYTES];
    puts("Enter Password");
    char password[100];
    scanf("%s", password);
    if (hash(password, hashed_password) != 0) {
        return -1;
    }

    puts("re-enter password");
    char password_attempt[100];
    scanf("%s", password_attempt);

    if (check(password_attempt, hashed_password) != 0)
        return 1;
    return 0;
}

int main(void) {
    atexit(onClose);

    if (sodium_init() < 0) {
        exit(EXIT_FAILURE);
    };

    switch (createMasterPassword()) {
        case -1:
            puts("out of memory");
            break;
        case 0:
            puts("password hash successful");
            break;
        default:
            puts("Password attempt failed");
    }
}
