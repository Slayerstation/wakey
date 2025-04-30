#ifndef UNIT_TEST
#define UNIT_TEST
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// Include the production code. Make sure that in wakey19.c, the main() is wrapped like this:
//
//   #ifndef UNIT_TEST
//   int main(int argc, char *argv[]) { ... }
//   #endif
//
#include "../wakey19.c"

// Unit test for string copy wrappers.
void test_my_strlcpy_and_safe_wrapper(void) {
    char dest[10];

    // Test my_strlcpy with a string that fits.
    size_t len = my_strlcpy(dest, "Hello", sizeof(dest));
    assert(len == 5);
    assert(strcmp(dest, "Hello") == 0);

    // Test my_strlcpy with a string that causes truncation.
    len = my_strlcpy(dest, "Hello, World!", sizeof(dest));
    assert(len == 13);  // the returned length is the full source string length.
    // Only 9 characters fit into dest (plus the terminating null).
    assert(strncmp(dest, "Hello, Wo", 9) == 0);

    // Test safe_strlcpy_wrapper (this will print a warning if truncation happens).
    memset(dest, 0, sizeof(dest));
    len = safe_strlcpy_wrapper(dest, "ThisIsTooLong", sizeof(dest), "test_my_strlcpy");
    assert(len == strlen("ThisIsTooLong"));
    // Expect that the destination is truncated to the maximum space available.
    assert(strlen(dest) == sizeof(dest) - 1);
}

// Unit test for safe_snprintf.
void test_safe_snprintf(void) {
    char buf[12];

    // Test safe_snprintf with a string that fits.
    int n = safe_snprintf(buf, sizeof(buf), "12345");
    assert(n == 5);
    assert(strcmp(buf, "12345") == 0);

    // This call is expected to cause truncation.
    n = safe_snprintf(buf, 6, "1234567890");
    // vsnprintf returns the length required even if truncation occurs.
    assert(n >= 10);
    // The buffer size is 6; thus only 5 characters are stored plus the null terminator.
    assert(strlen(buf) == 5);
}

int main(void) {
    test_my_strlcpy_and_safe_wrapper();
    test_safe_snprintf();
    printf("All unit tests passed.\n");
    return EXIT_SUCCESS;
}
