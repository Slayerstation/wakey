// tests/test_unit.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// “Unstatic” by redefining static to nothing for testing purposes.
// (Alternatively, refactor your code into a library with a public header.)
#ifdef UNIT_TEST
#undef static
#endif

// Include the source file
#include "../wakey19.c"

// Test for my_strlcpy and its safe wrapper.
void test_my_strlcpy_and_safe_wrapper() {
    char dest[10];
    // Test copying a string that fits.
    size_t len = my_strlcpy(dest, "Hello", sizeof(dest));
    assert(len == 5);
    assert(strcmp(dest, "Hello") == 0);
    
    // Test truncation
    len = my_strlcpy(dest, "Hello, World!", sizeof(dest));
    assert(len == 13);  // returned length of source
    // With a size of 10, only 9 characters are copied and a null terminator appended.
    assert(strncmp(dest, "Hello, Wo", 9) == 0);
    
    // The safe wrapper prints a warning on truncation.
    memset(dest, 0, sizeof(dest));
    len = safe_strlcpy_wrapper(dest, "ThisIsTooLong", sizeof(dest), "test_my_strlcpy");
    assert(len == strlen("ThisIsTooLong"));
    // Expect truncation as there is not enough room.
    assert(strlen(dest) == sizeof(dest) - 1);
}

// Test safe_snprintf
void test_safe_snprintf() {
    char buf[12];
    int n = safe_snprintf(buf, sizeof(buf), "12345");
    assert(n == 5);
    assert(strcmp(buf, "12345") == 0);

    // This call is expected to generate a warning due to truncation.
    n = safe_snprintf(buf, 6, "1234567890");
    // Even if truncated, vsnprintf returns the required length
    assert(n >= 10);
    // The buffer should hold only 5 characters plus null terminator.
    assert(strlen(buf) == 5);
}

int main(void) {
    test_my_strlcpy_and_safe_wrapper();
    test_safe_snprintf();
    printf("All unit tests passed.\n");
    return EXIT_SUCCESS;
}
