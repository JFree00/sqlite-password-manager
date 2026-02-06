#include <stdlib.h>

void onClose() {
}


int main(void) {
    atexit(onClose);
}
