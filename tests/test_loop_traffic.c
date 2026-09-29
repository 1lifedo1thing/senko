#include "../daemon/loop.c"
#include <assert.h>
#include <stdlib.h>

static int unused_dial(void *ctx) {
    (void)ctx;
    abort();
}

/* a server slower than the app must slow the app down, never drop what the
   app already sent. the loop used to read the socket, offer the bytes to a
   full session and throw away the part it refused */
static void upload_survives_slow_server(void) {
    loop_t *lp = calloc(1, sizeof *lp);
    assert(lp);
    lp->listen_fd = lp->wake_rd = lp->wake_wr = -1;
    int local[2], remote[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, local) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, remote) == 0);
    int small = 4096;
    assert(setsockopt(remote[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof small) == 0);
    assert(setsockopt(remote[1], SOL_SOCKET, SO_RCVBUF, &small, sizeof small) == 0);
    for (int i = 0; i < 2; ++i) {
        set_nonblock(local[i]);
        set_nonblock(remote[i]);
    }
    loop_conn_t *c = &lp->conns[0];
    c->owner = lp;
    c->local_fd = local[0];
    c->remote_fd = remote[0];
    c->used = 1;
    c->open_vt = &transport_tcp;
    c->th = transport_tcp.open(remote[0], NULL);
    assert(session_init(&c->sess, &transport_tcp, c->th, VL_PROTO_HTTP,
                        NULL, NULL, NULL, NULL) == SESS_OK);
    c->sess.state = SESS_RELAY;

    /* the app pushes as much as its socket takes while the server reads nothing */
    static uint8_t pattern[8192];
    for (size_t i = 0; i < sizeof pattern; ++i) pattern[i] = (uint8_t)(i * 7u);
    size_t sent = 0;
    for (int round = 0; round < 32; ++round) {
        ssize_t w = write(local[1], pattern, sizeof pattern);
        if (w > 0) sent += (size_t)w;
        service_conn(lp, c, POLLIN, 0);
    }
    assert(sent > 64 * 1024); /* more than the session can hold at once */

    /* then the server reads everything, and the loop keeps pumping */
    static uint8_t sink[65536];
    size_t received = 0;
    for (int round = 0; round < 4000 && received < sent; ++round) {
        ssize_t r;
        while ((r = read(remote[1], sink, sizeof sink)) > 0) received += (size_t)r;
        service_conn(lp, c, POLLIN, POLLOUT);
    }
    assert(received == sent);
    drop_conn(lp, c);
    close(local[1]);
    close(remote[1]);
    free(lp);
}

/* the managed loop shares one poll with the control server and waits as long
   as its nearest deadline: forever when relays only wait on their sockets,
   and no longer than a vision bootstrap's first write deadline */
static void prepare_waits_for_deadlines(void) {
    loop_t *lp = calloc(1, sizeof *lp);
    assert(lp);
    lp->listen_fd = lp->wake_rd = lp->wake_wr = -1;
    static struct pollfd pfd[LOOP_POLL_MAX];
    int wait = -1;
    assert(loop_prepare(lp, pfd, LOOP_POLL_MAX - 1, &wait) == 0);
    assert(loop_prepare(lp, pfd, LOOP_POLL_MAX, &wait) == 2 && wait == -1);

    loop_conn_t *c = &lp->conns[0];
    c->owner = lp;
    c->used = 1;
    c->local_fd = c->remote_fd = -1;
    c->sess.state = SESS_RELAY;
    wait = -1;
    assert(loop_prepare(lp, pfd, LOOP_POLL_MAX, &wait) == 4 && wait == -1);
    assert(lp->poll_conn[2] == c && !lp->poll_remote[2]);
    assert(lp->poll_conn[3] == c && lp->poll_remote[3]);

    c->sess.state = SESS_VISION_FIRST;
    c->sess.vision_first_deadline_ms = (long)(senko_now_ms() + 300);
    wait = -1;
    loop_prepare(lp, pfd, LOOP_POLL_MAX, &wait);
    assert(wait > 0 && wait <= 300);
    wait = 20;
    loop_prepare(lp, pfd, LOOP_POLL_MAX, &wait);
    assert(wait == 20); /* a sooner deadline from another owner stands */
    free(lp);
}

int main(void) {
    loop_t *lp = calloc(1, sizeof *lp);
    assert(lp);
    lp->listen_fd = lp->wake_rd = lp->wake_wr = -1;
    int local[2], remote[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, local) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, remote) == 0);
    set_nonblock(local[0]);
    set_nonblock(local[1]);
    set_nonblock(remote[0]);
    set_nonblock(remote[1]);
    loop_conn_t *c = &lp->conns[0];
    c->owner = lp;
    c->local_fd = local[0];
    c->remote_fd = remote[0];
    c->used = 1;
    c->open_vt = &transport_tcp;
    c->th = transport_tcp.open(remote[0], NULL);
    assert(session_init(&c->sess, &transport_tcp, c->th, VL_PROTO_HTTP,
                        NULL, NULL, NULL, NULL) == SESS_OK);
    c->sess.state = SESS_RELAY;
    assert(write(local[1], "early", 5) == 5);
    assert(read_local_into_prebuf(c) == 0);
    assert(lp->bytes_up == 5 && c->prebuf_len == 5);
    assert(write(local[1], "upload", 6) == 6);
    service_conn(lp, c, POLLIN, 0);
    char data[8192];
    /* bytes still waiting in the prebuf go out first and in order; they used
       to stay there for good once the relay had started */
    assert(read(remote[1], data, sizeof data) == 11);
    assert(memcmp(data, "earlyupload", 11) == 0 && lp->bytes_up == 11);
    assert(c->prebuf_len == 0);
    assert(write(remote[1], "download", 8) == 8);
    service_conn(lp, c, 0, POLLIN);
    assert(read(local[1], data, sizeof data) == 8);
    assert(memcmp(data, "download", 8) == 0 && lp->bytes_down == 8);

    int small = 1024;
    assert(setsockopt(local[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof small) == 0);
    memset(c->pend, 'x', sizeof c->pend);
    c->pend_len = sizeof c->pend;
    assert(flush_pend_local(c) == 0);
    assert(c->pend_off > 0 && c->pend_off < c->pend_len);
    assert(lp->bytes_down == 8 + c->pend_off);
    uint64_t before = lp->bytes_down;
    assert(flush_to_local(c) == 0 && lp->bytes_down == before);
    for (int i = 0; i < 100 && c->pend_len; ++i) {
        while (read(local[1], data, sizeof data) > 0) {}
        assert(flush_to_local(c) == 0);
    }
    assert(c->pend_len == 0 && lp->bytes_down == 8 + sizeof c->pend);
    drop_conn(lp, c);
    assert(lp->bytes_up == 11 && lp->bytes_down == 8 + sizeof c->pend);
    close(local[1]);
    close(remote[1]);
    assert(loop_set_server(lp, &transport_tcp, unused_dial, NULL, VL_PROTO_HTTP,
                          NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                          NULL, NULL, NULL, NULL, 0) == LOOP_OK);
    assert(lp->bytes_up == 0 && lp->bytes_down == 0);
    lp->bytes_up = UINT64_C(1) << 35;
    lp->bytes_down = 123;
    loop_stop(lp);
    assert(lp->bytes_up == 0 && lp->bytes_down == 0);
    free(lp);
    upload_survives_slow_server();
    prepare_waits_for_deadlines();
    puts("all loop traffic checks passed");
    return 0;
}
