// tests/test_unit.c

// Only define UNIT_TEST if it hasn't been defined already (for example via the compiler command line).
#ifndef UNIT_TEST
#define UNIT_TEST
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// Include the production code.
// Ensure that in wakey19.c, the main() function is wrapped as shown above so that it is not compiled during unit testing.
#include "../wakey.c"

// Unit test for the string copy wrappers.
void test_my_strlcpy_and_safe_wrapper(void) {
    char dest[10];

    // Test my_strlcpy with a string that fits.
    size_t len = my_strlcpy(dest, "Hello", sizeof(dest));
    assert(len == 5);
    assert(strcmp(dest, "Hello") == 0);

    // Test my_strlcpy with truncation.
    len = my_strlcpy(dest, "Hello, World!", sizeof(dest));
    assert(len == 13);  // full source string length returned.
    // Only 9 characters will be copied into dest (plus the null terminator).
    assert(strncmp(dest, "Hello, Wo", 9) == 0);

    // Test safe_strlcpy_wrapper; note that it prints a warning when truncation occurs.
    memset(dest, 0, sizeof(dest));
    len = safe_strlcpy_wrapper(dest, "ThisIsTooLong", sizeof(dest), "test_my_strlcpy");
    assert(len == strlen("ThisIsTooLong"));
    // The string must be truncated because the destination can only hold 9 characters plus the null terminator.
    assert(strlen(dest) == sizeof(dest) - 1);
}

// Unit test for safe_snprintf.
void test_safe_snprintf(void) {
    char buf[12];

    // Test safe_snprintf with a string that fits.
    int n = safe_snprintf(buf, sizeof(buf), "12345");
    assert(n == 5);
    assert(strcmp(buf, "12345") == 0);

    // Test safe_snprintf when truncation should occur.
    n = safe_snprintf(buf, 6, "1234567890");
    // vsnprintf returns the full length required, even if truncation occurs.
    assert(n >= 10);
    // The buffer size (6) means that only 5 characters are stored plus the null terminator.
    assert(strlen(buf) == 5);
}

int main(void) {
    test_my_strlcpy_and_safe_wrapper();
    test_safe_snprintf();
    printf("All unit tests passed.\n");
    return EXIT_SUCCESS;
}
