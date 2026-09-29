/* checked against python's hashlib.blake2b(data, digest_size=32); nothing in
   the tree tested this hash before, and a hand-rolled compress function is
   exactly where a wrong rotation or sigma entry hides */
#include "blake2b256.h"

#include <stdio.h>
#include <string.h>

static int failed;

static void expect(const char *label, const void *data, size_t len,
                   const char *want_hex) {
    unsigned char out[32];
    char got_hex[65];
    blake2b256(data, len, out);
    for (int i = 0; i < 32; ++i) sprintf(got_hex + i * 2, "%02x", out[i]);
    got_hex[64] = '\0';
    if (strcmp(got_hex, want_hex) != 0) {
        fprintf(stderr, "FAIL %s: want %s got %s\n", label, want_hex, got_hex);
        failed = 1;
    }
}

int main(void) {
    char a[201];
    memset(a, 'a', sizeof a);

    expect("empty input", "", 0,
          "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8");
    expect("abc", "abc", 3,
          "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319");
    expect("hello world", "hello world", 11,
          "256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610");
/* one block exactly: the buffered bytes must not get compressed early */
    expect("128 bytes, one full block", a, 128,
          "ae2aa48507885c4c950fb809b2076f959cde9f8ea6da260d9a3587df33dac450");
/* one block plus one byte: the first block has to compress before buffering
   the rest, not just once the whole input is in */
    expect("129 bytes, block boundary", a, 129,
          "2f64744a6de0d2c0b56e64cf6e29a5aaa255010d415d51c75ccc82f73dccd865");
    expect("200 bytes, two blocks", a, 200,
          "6b6e59aaf00eb730cf93de53560846722184bbd92f8368c21ffa95380c2f9fe6");

    if (failed) {
        printf("blake2b256 checks failed\n");
        return 1;
    }
    printf("all blake2b256 checks passed\n");
    return 0;
}
