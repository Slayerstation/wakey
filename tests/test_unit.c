// tests/test_unit.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// Define UNIT_TEST so that the main() from wakey19.c is excluded.
#define UNIT_TEST
#include "../wakey19.c"

// Unit test for string copy wrappers.
void test_my_strlcpy_and_safe_wrapper() {
    char dest[10];

    // Test my_strlcpy with a string that fits.
    size_t len = my_strlcpy(dest, "Hello", sizeof(dest));
    assert(len == 5);
    assert(strcmp(dest, "Hello") == 0);

    // Test my_strlcpy with truncation.
    len = my_strlcpy(dest, "Hello, World!", sizeof(dest));
    assert(len == 13);  // returned source length.
    // dest can hold only 9 characters plus the null terminator.
    assert(strncmp(dest, "Hello, Wo", 9) == 0);

    // Test safe_strlcpy_wrapper (this will print a warning if truncation occurs).
    memset(dest, 0, sizeof(dest));
    len = safe_strlcpy_wrapper(dest, "ThisIsTooLong", sizeof(dest), "test_my_strlcpy");
    assert(len == strlen("ThisIsTooLong"));
    // Expect truncation as the buffer can hold only 9 characters + null terminator.
    assert(strlen(dest) == sizeof(dest) - 1);
}

// Unit test for safe_snprintf.
void test_safe_snprintf() {
    char buf[12];

    // Test safe_snprintf with a string that fits.
    int n = safe_snprintf(buf, sizeof(buf), "12345");
    assert(n == 5);
    assert(strcmp(buf, "12345") == 0);

    // This call should trigger a warning due to truncation.
    n = safe_snprintf(buf, 6, "1234567890");
    // vsnprintf returns the required length in case of truncation.
    assert(n >= 10);
    // The buffer can hold only 5 characters plus a null terminator, so the length is 5.
    assert(strlen(buf) == 5);
}

int main(void) {
    test_my_strlcpy_and_safe_wrapper();
    test_safe_snprintf();
    printf("All unit tests passed.\n");
    return EXIT_SUCCESS;
}
