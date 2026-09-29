/* how a session tells a server's reset from a server's clean end, over a real
   loopback tcp connection, because only tcp carries a reset. both frontends
   rely on it: a reset has to reach the app as a reset, never as a clean close
   of a stream that was cut */

#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "session.h"

static int failures;

static void ok(const char *name, int condition) {
    if (condition) return;
    ++failures;
    fprintf(stderr, "FAIL %s\n", name);
}

/* a connected pair of loopback tcp sockets: the session's end and the server's */
static int tcp_pair(int *client, int *server) {
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener, (struct sockaddr *)&a, sizeof a) != 0) return -1;
    socklen_t len = sizeof a;
    getsockname(listener, (struct sockaddr *)&a, &len);
    listen(listener, 1);
    *client = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(*client, (struct sockaddr *)&a, sizeof a) != 0) return -1;
    *server = accept(listener, NULL, NULL);
    close(listener);
    if (*server < 0) return -1;
    int flags = fcntl(*client, F_GETFL, 0);
    if (flags < 0 || fcntl(*client, F_SETFL, flags | O_NONBLOCK) != 0) return -1;
    return 0;
}

static void relaying_session(session_t *s, int fd) {
    void *th = transport_tcp.open(fd, NULL);
    session_init(s, &transport_tcp, th, VL_PROTO_HTTP, NULL, NULL, NULL, NULL);
    s->state = SESS_RELAY;
}

/* wait until the session's socket has something to report, a fin, a reset
   or bytes, instead of guessing how long the loopback takes */
static void settle(int fd) {
    struct pollfd p = { fd, POLLIN, 0 };
    poll(&p, 1, 2000);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    static session_t s;
    int client, server;

    /* a server that resets: the session fails, it does not close cleanly */
    ok("loopback pair", tcp_pair(&client, &server) == 0);
    relaying_session(&s, client);
    struct linger hard = { 1, 0 };
    setsockopt(server, SOL_SOCKET, SO_LINGER, &hard, sizeof hard);
    close(server);
    settle(client);
    ok("a reset from the server is an error", session_pump_remote(&s) == SESS_ERR &&
       s.state == SESS_ERROR);
    close(client);

    /* a server that ends cleanly: the session closes, it does not fail */
    ok("loopback pair", tcp_pair(&client, &server) == 0);
    relaying_session(&s, client);
    ok("the server's last bytes", write(server, "bye", 3) == 3);
    shutdown(server, SHUT_WR);
    settle(client);
    ok("a clean end from the server closes the session",
       session_pump_remote(&s) == SESS_OK && s.state == SESS_CLOSED);
    uint8_t got[8];
    ok("and the last bytes are kept for the client",
       session_take_client(&s, got, sizeof got) == 3 && memcmp(got, "bye", 3) == 0);
    close(server);
    close(client);

    /* the relay passed the client's half close on: the session keeps reading
       what the server still sends instead of failing on its own shut write */
    ok("loopback pair", tcp_pair(&client, &server) == 0);
    relaying_session(&s, client);
    shutdown(client, SHUT_WR);
    ok("the server answers after the client's half close", write(server, "late", 4) == 4);
    settle(client);
    ok("a half closed session still reads the answer",
       session_pump_remote(&s) == SESS_OK && s.state == SESS_RELAY &&
       session_take_client(&s, got, sizeof got) == 4 && memcmp(got, "late", 4) == 0);
    close(server);
    close(client);

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    puts("all session reset checks passed");
    return 0;
}
