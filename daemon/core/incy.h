#ifndef INCY_H
#define INCY_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    INCY_OK = 0,
    INCY_ERR_SCHEME,      /* not an incy:// link */
    INCY_ERR_UNSUPPORTED, /* an incy:// action that does not import a source */
    INCY_ERR_MALFORMED,   /* empty payload, bad encoding, bad json or url */
    INCY_ERR_TOO_LONG,
    INCY_ERR_DECRYPT      /* crypt1 payload that fails the tag check */
} incy_status_t;

/* incy://add/<x>, incy://import/<x> and incy://crypt1/<payload>.
   out gets the source: the subscription url for crypt1, the text after the
   action word for add and import (an http(s) url, a node link, a link list or
   a base64 body, left for the caller to classify). name gets the display name
   when the link carries one (crypt1 "n" field, or the fragment of an http(s)
   url), cut to fit at a utf-8 boundary; it is empty otherwise */
incy_status_t incy_unwrap(const char *link, char *out, size_t out_cap,
                          char *name, size_t name_cap);

#ifdef __cplusplus
}
#endif

#endif /* incy_h */
