#ifndef SENKO_APP_PROXY_H
#define SENKO_APP_PROXY_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* the connect hook: senkotlsfix sends the connections of hooked processes to
   senkod's socks port, which it learns from a small state file. it covers only
   hooked processes, so it is what runs when no tunnel can be opened */
typedef struct {
    int active;
    int socks_port;
} app_proxy_t;

/* senkotlsfix is installed where substrate loads it */
int app_proxy_available(void);

/* publishes the socks port; 0 on success, -1 with the reason */
int app_proxy_start(app_proxy_t *proxy, int socks_port, char *reason, size_t reason_cap);

/* withdraws the state file, so hooked processes stop being sent to senkod */
void app_proxy_stop(app_proxy_t *proxy);

#ifdef __cplusplus
}
#endif

#endif
