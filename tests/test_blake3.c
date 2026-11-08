#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blake3.h"

static const struct { size_t len; const char *hash; const char *derived; } vec[] = {
#include "blake3_vectors.inc"
};

static void hex(const uint8_t *b, size_t n, char *out) {
    for (size_t i = 0; i < n; ++i) sprintf(out + 2 * i, "%02x", b[i]);
}

int main(void) {
    for (size_t v = 0; v < sizeof vec / sizeof vec[0]; ++v) {
        size_t n = vec[v].len;
        uint8_t *in = malloc(n ? n : 1);
        assert(in);
        for (size_t i = 0; i < n; ++i) in[i] = (uint8_t)(i % 251);

        uint8_t out[32];
        char text[65];
        blake3_hash(in, n, out);
        hex(out, 32, text);
        if (strcmp(text, vec[v].hash) != 0) {
            fprintf(stderr, "hash len %zu: %s != %s\n", n, text, vec[v].hash);
            return 1;
        }

        /* odd split sizes must give the same answer as one update */
        blake3_t h;
        blake3_init(&h);
        for (size_t off = 0, step = 1; off < n; off += step, step = step * 3 + 1) {
            size_t take = n - off < step ? n - off : step;
            blake3_update(&h, in + off, take);
        }
        blake3_final(&h, out);
        hex(out, 32, text);
        if (strcmp(text, vec[v].hash) != 0) {
            fprintf(stderr, "split hash len %zu\n", n);
            return 1;
        }

        size_t cl = n > 100 ? n / 3 : n;
        blake3_derive_key(in, cl, in, n, out);
        hex(out, 32, text);
        if (strcmp(text, vec[v].derived) != 0) {
            fprintf(stderr, "derive len %zu: %s != %s\n", n, text, vec[v].derived);
            return 1;
        }
        free(in);
    }
    puts("test_blake3: ok");
    return 0;
}
