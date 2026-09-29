#ifndef REAL_PROBE_H
#define REAL_PROBE_H

#include <stddef.h>

#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* the host every probe asks through the server. it answers 204 with no body
   and is reachable from every region a panel sells nodes in */
#define REAL_PROBE_HOST "www.gstatic.com"
#define REAL_PROBE_PORT 80

/* lets the caller pin the probe socket to the physical interface before it
   connects, so a running tunnel cannot answer the handshake itself */
typedef void (*real_probe_bind_fn)(int fd);

/* the delay a user actually waits for: tcp to the server, its tls or reality
   handshake, the proxy request and one http answer from REAL_PROBE_HOST
   carried back through it. a tcp connect alone measures the nearest cdn edge
   when a node sits behind one, which read as 2 ms for a server abroad.
   ip is the server's resolved ipv4 address. returns milliseconds, or -1 with
   the failed stage in reason */
int real_probe_run(const vl_server_t *server, const char *ip,
                   real_probe_bind_fn bind_fd, int timeout_ms,
                   char *reason, size_t reason_cap);

/* whether an answer from REAL_PROBE_HOST starts like an http status line */
int real_probe_answer_ok(const char *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* real_probe_h */
