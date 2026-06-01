/* Minimal C example for the rgb-lightning-node c-ffi bindings.
 *
 * What it does:
 *   1. Calls `rln_uniffi_healthcheck()` and prints the result.
 *   2. Calls `rln_uniffi_is_initialized()` and prints the result.
 *
 * Both calls work without a running node — they exercise just the FFI plumbing.
 *
 * Build:
 *     make
 *     ./example
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rln.h"

static void print_result(const char *label, struct CResultString r) {
    if (r.result == Ok) {
        printf("[%s] OK: %s\n", label, r.inner ? r.inner : "(null)");
    } else {
        printf("[%s] ERR: %s\n", label, r.inner ? r.inner : "(null)");
    }
    rln_free_string(r.inner);
}

int main(void) {
    printf("rgb-lightning-node c-ffi smoke test\n");

    print_result("healthcheck", rln_uniffi_healthcheck());
    print_result("is_initialized", rln_uniffi_is_initialized());

    return 0;
}
