/* a trojan session against a local server on the other end of a socket pair:
   the request the server parses, an echoed exchange in both directions, and
   what the client sees when the credentials or the outer handshake fail */
#define _DEFAULT_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "session.h"
#include "transport.h"
#include "trojan_client.h"

static int failed;

static void ok(const char *name, int cond) {
    if (!cond) {
        printf("FAIL %s\n", name);
        failed++;
    }
}

typedef struct {
    int fd;
    char want_hash[TROJAN_HEX_LEN + 1];
    uint8_t in[16384];    /* the first reads: the header and whatever rides behind it */
    size_t in_len;
    int header_done;
    int rejected;         /* wrong hash: the connection was closed */
    uint8_t atyp;
    uint8_t addr[256];
    size_t addr_len;
    uint16_t port;
    size_t payload_seen;
    int echo;             /* send the payload back */
    int closed_by_client;
    uint8_t *out;         /* echo not yet accepted by the socket */
    size_t out_len, out_cap;
} server_t;

static void nonblock(int fd) { fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK); }

static void server_init(server_t *s, int fd, const char *password) {
    memset(s, 0, sizeof *s);
    s->fd = fd;
    s->echo = 1;
    trojan_hash_password(password, s->want_hash);
}

/* the client only reads between server steps, so a full socket must not block */
static void server_flush(server_t *s) {
    size_t off = 0;
    while (s->fd >= 0 && off < s->out_len) {
        ssize_t w = write(s->fd, s->out + off, s->out_len - off);
        if (w > 0) { off += (size_t)w; continue; }
        break;
    }
    memmove(s->out, s->out + off, s->out_len - off);
    s->out_len -= off;
}

static void server_send(server_t *s, const uint8_t *p, size_t n) {
    if (s->out_len + n > s->out_cap) {
        s->out_cap = (s->out_len + n) * 2;
        s->out = realloc(s->out, s->out_cap);
        if (!s->out) abort();
    }
    memcpy(s->out + s->out_len, p, n);
    s->out_len += n;
    server_flush(s);
}

/* the header is hash CRLF cmd atyp addr port CRLF; whatever follows is payload */
static void server_header(server_t *s) {
    size_t at = TROJAN_HEX_LEN;
    size_t need;
    if (s->in_len < at + 2 + 2) return;
    if (memcmp(s->in, s->want_hash, TROJAN_HEX_LEN) != 0 || s->in[at] != '\r' || s->in[at + 1] != '\n') {
        s->rejected = 1;
        close(s->fd);
        s->fd = -1;
        return;
    }
    at += 2;
    if (s->in[at] != 0x01) { s->rejected = 1; close(s->fd); s->fd = -1; return; }
    s->atyp = s->in[at + 1];
    at += 2;
    if (s->atyp == 0x01) s->addr_len = 4;
    else if (s->atyp == 0x04) s->addr_len = 16;
    else if (s->atyp == 0x03) {
        if (s->in_len < at + 1) return;
        s->addr_len = s->in[at++];
    } else { s->rejected = 1; close(s->fd); s->fd = -1; return; }
    need = at + s->addr_len + 2 + 2;
    if (s->in_len < need) return;
    memcpy(s->addr, s->in + at, s->addr_len);
    at += s->addr_len;
    s->port = (uint16_t)(s->in[at] << 8 | s->in[at + 1]);
    at += 2;
    if (s->in[at] != '\r' || s->in[at + 1] != '\n') { s->rejected = 1; close(s->fd); s->fd = -1; return; }
    at += 2;
    s->header_done = 1;
    s->payload_seen = s->in_len - at;
    if (s->echo && s->payload_seen) server_send(s, s->in + at, s->payload_seen);
}

static void server_step(server_t *s) {
    uint8_t buf[8192];
    ssize_t n;
    if (s->fd < 0) return;
    server_flush(s);
    while ((n = read(s->fd, buf, sizeof buf)) > 0) {
        if (!s->header_done) {
            if (s->in_len + (size_t)n > sizeof s->in) { s->rejected = 1; close(s->fd); s->fd = -1; return; }
            memcpy(s->in + s->in_len, buf, (size_t)n);
            s->in_len += (size_t)n;
            server_header(s);
            if (s->fd < 0) return;
        } else {
            s->payload_seen += (size_t)n;
            if (s->echo) server_send(s, buf, (size_t)n);
        }
    }
    if (n == 0) s->closed_by_client = 1;
}

typedef struct {
    int cfd;
    server_t srv;
    const transport_vt_t *vt;
    void *th;
    session_t sess;
} rig_t;

static int rig_open(rig_t *r, const char *client_password, const char *server_password) {
    int sv[2];
    memset(r, 0, sizeof *r);
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return -1;
    nonblock(sv[0]);
    nonblock(sv[1]);
    r->cfd = sv[0];
    server_init(&r->srv, sv[1], server_password);
    r->vt = &transport_tcp;
    r->th = r->vt->open(r->cfd, NULL);
    if (!r->th) return -1;
    return session_init(&r->sess, r->vt, r->th, VL_PROTO_TROJAN, NULL, NULL, NULL,
                        client_password) == SESS_OK ? 0 : -1;
}

static void rig_close(rig_t *r) {
    if (r->th) r->vt->close(r->th);
    close(r->cfd);
    if (r->srv.fd >= 0) close(r->srv.fd);
    free(r->srv.out);
}

/* send len bytes after the request, read back what the server returns */
static int rig_exchange(rig_t *r, const vless_dest_t *dest, const uint8_t *msg, size_t len,
                        uint8_t *back, size_t *back_len) {
    size_t first = len < 300 ? len : 300, used = 0, sent, got = 0;
    sess_status_t st = session_start_from_transparent_dest(&r->sess, dest, msg, first, &used);
    if (st != SESS_OK) return -1;
    sent = used;
    for (int i = 0; i < 200000 && got < len; ++i) {
        size_t c = 0;
        if (sent < len) {
            if (session_feed_client(&r->sess, msg + sent, len - sent, &c) != SESS_OK) break;
            sent += c;
        }
        server_step(&r->srv);
        if (session_pump_remote(&r->sess) != SESS_OK) break;
        got += session_take_client(&r->sess, back + got, len - got);
        if (session_is_done(&r->sess)) {
            got += session_take_client(&r->sess, back + got, len - got);
            break;
        }
    }
    *back_len = got;
    return 0;
}

static void fill(uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; ++i) p[i] = (uint8_t)(i * 31 + 7);
}

static void test_exchange(void) {
    static uint8_t msg[200 * 1024], back[200 * 1024];
    size_t got = 0;
    rig_t r;
    vless_dest_t d;

    fill(msg, sizeof msg);
    memset(&d, 0, sizeof d);
    d.atyp = VLESS_ADDR_DOMAIN;
    snprintf(d.domain, sizeof d.domain, "example.com");
    d.port = 443;
    ok("rig opens", rig_open(&r, "hunter2", "hunter2") == 0);
    ok("exchange runs", rig_exchange(&r, &d, msg, sizeof msg, back, &got) == 0);
    ok("the server parsed the header", r.srv.header_done && !r.srv.rejected &&
       r.srv.atyp == 0x03 && r.srv.addr_len == 11 && memcmp(r.srv.addr, "example.com", 11) == 0 &&
       r.srv.port == 443);
    ok("200 kb came back whole and in order", got == sizeof msg && memcmp(back, msg, got) == 0);
    ok("the server saw every byte once", r.srv.payload_seen == sizeof msg);
    rig_close(&r);

    memset(&d, 0, sizeof d);
    d.atyp = VLESS_ADDR_IPV4;
    d.host_addr[0] = 203; d.host_addr[1] = 0; d.host_addr[2] = 113; d.host_addr[3] = 7;
    d.port = 8443;
    ok("ipv4 rig opens", rig_open(&r, "hunter2", "hunter2") == 0);
    ok("ipv4 exchange", rig_exchange(&r, &d, msg, 1000, back, &got) == 0 && got == 1000 &&
       memcmp(back, msg, 1000) == 0);
    ok("ipv4 header", r.srv.atyp == 0x01 && r.srv.addr_len == 4 &&
       memcmp(r.srv.addr, d.host_addr, 4) == 0 && r.srv.port == 8443);
    rig_close(&r);

    memset(&d, 0, sizeof d);
    d.atyp = VLESS_ADDR_IPV6;
    d.host_addr[0] = 0x20; d.host_addr[1] = 0x01; d.host_addr[15] = 1;
    d.port = 53;
    ok("ipv6 rig opens", rig_open(&r, "hunter2", "hunter2") == 0);
    ok("ipv6 exchange", rig_exchange(&r, &d, msg, 64, back, &got) == 0 && got == 64);
    ok("ipv6 header", r.srv.atyp == 0x04 && r.srv.addr_len == 16 &&
       memcmp(r.srv.addr, d.host_addr, 16) == 0 && r.srv.port == 53);
    rig_close(&r);
}

/* the catalog keeps 255 bytes and the server hashes all of them */
static void test_long_password(void) {
    char pw[256];
    uint8_t msg[512], back[512];
    size_t got = 0;
    rig_t r;
    vless_dest_t d;

    memset(pw, 'k', 255);
    pw[255] = '\0';
    memset(&d, 0, sizeof d);
    d.atyp = VLESS_ADDR_DOMAIN;
    snprintf(d.domain, sizeof d.domain, "example.com");
    d.port = 443;
    fill(msg, sizeof msg);
    ok("long password rig", rig_open(&r, pw, pw) == 0);
    ok("long password exchange", rig_exchange(&r, &d, msg, sizeof msg, back, &got) == 0 &&
       !r.srv.rejected && got == sizeof msg);
    rig_close(&r);
}

static void test_wrong_credentials(void) {
    uint8_t msg[2048], back[2048];
    size_t got = 0;
    rig_t r;
    vless_dest_t d;

    memset(&d, 0, sizeof d);
    d.atyp = VLESS_ADDR_DOMAIN;
    snprintf(d.domain, sizeof d.domain, "example.com");
    d.port = 443;
    fill(msg, sizeof msg);
    ok("wrong password rig", rig_open(&r, "hunter2", "hunter3") == 0);
    ok("wrong password runs", rig_exchange(&r, &d, msg, sizeof msg, back, &got) == 0);
    ok("the server refused it", r.srv.rejected && !r.srv.header_done);
    ok("no payload came back", got == 0);
    ok("the session ends instead of waiting", session_is_done(&r.sess));
    rig_close(&r);

    /* one byte of difference at the end of the password is another hash */
    ok("near miss rig", rig_open(&r, "hunter2", "hunter2 ") == 0);
    ok("near miss runs", rig_exchange(&r, &d, msg, 100, back, &got) == 0);
    ok("a trailing space is another password", r.srv.rejected && got == 0);
    rig_close(&r);
}

/* the server goes away after answering part of the data */
static void test_server_closes_early(void) {
    uint8_t msg[4096], back[4096];
    size_t got = 0;
    rig_t r;
    vless_dest_t d;

    memset(&d, 0, sizeof d);
    d.atyp = VLESS_ADDR_DOMAIN;
    snprintf(d.domain, sizeof d.domain, "example.com");
    d.port = 443;
    fill(msg, sizeof msg);
    ok("early close rig", rig_open(&r, "hunter2", "hunter2") == 0);
    ok("start", session_start_from_transparent_dest(&r.sess, &d, msg, 200, &(size_t){0}) == SESS_OK);
    server_step(&r.srv);
    ok("the first answer arrives", session_pump_remote(&r.sess) == SESS_OK &&
       session_take_client(&r.sess, back, sizeof back) == 200 && memcmp(back, msg, 200) == 0);
    close(r.srv.fd);
    r.srv.fd = -1;
    for (int i = 0; i < 100 && !session_is_done(&r.sess); ++i)
        (void)session_pump_remote(&r.sess);
    got = session_take_client(&r.sess, back, sizeof back);
    ok("the session notices the close", session_is_done(&r.sess) && got == 0);
    rig_close(&r);
}

/* a server that does not speak tls: nothing of the trojan request may leave in
   the clear, and the failure has to surface instead of hanging */
static void test_outer_handshake_failure(void) {
    int sv[2];
    transport_tls_cfg_t cfg;
    void *th;
    uint8_t buf[4096], seen[16384];
    size_t seen_len = 0;
    int rc = 0, answered = 0;
    char hash[TROJAN_HEX_LEN + 1];
    uint8_t request[200];
    size_t request_len = 0;
    trojan_client_t tc;
    vless_dest_t d;

    ok("socket pair", socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    nonblock(sv[0]);
    nonblock(sv[1]);
    memset(&cfg, 0, sizeof cfg);
    cfg.sni = "srv.example";
    cfg.peer_host = "srv.example";
    cfg.peer_port = 443;
    th = transport_tls.open(sv[0], &cfg);
    ok("tls transport opens", th != NULL);
    if (!th) return;

    memset(&d, 0, sizeof d);
    d.atyp = VLESS_ADDR_DOMAIN;
    snprintf(d.domain, sizeof d.domain, "example.com");
    d.port = 443;
    trojan_client_init(&tc, "hunter2", &d);
    ok("request", trojan_client_build_request(&tc, NULL, 0, request, sizeof request,
                                              &request_len) == 0);
    trojan_hash_password("hunter2", hash);

    for (int i = 0; i < 20000 && rc >= 0 && rc != TRANSPORT_ERR && rc != TRANSPORT_EOF; ++i) {
        ssize_t n;
        int w = transport_tls.write(th, request, request_len);
        if (w == TRANSPORT_ERR || w == TRANSPORT_EOF) { rc = w; break; }
        while ((n = read(sv[1], buf, sizeof buf)) > 0) {
            if (seen_len + (size_t)n <= sizeof seen) {
                memcpy(seen + seen_len, buf, (size_t)n);
                seen_len += (size_t)n;
            }
            if (!answered) {
                static const char reply[] = "HTTP/1.1 400 Bad Request\r\n\r\n";
                ssize_t wr = write(sv[1], reply, sizeof reply - 1);
                (void)wr;
                answered = 1;
            }
        }
        rc = transport_tls.read(th, buf, sizeof buf);
        if (rc > 0) rc = 0;
    }
    ok("the handshake failure is reported", rc == TRANSPORT_ERR || rc == TRANSPORT_EOF);
    ok("the client hello went out", seen_len > 0 && seen[0] == 0x16);
    {
        int leaked = 0;
        for (size_t i = 0; i + TROJAN_HEX_LEN <= seen_len; ++i)
            if (memcmp(seen + i, hash, TROJAN_HEX_LEN) == 0) leaked = 1;
        ok("the password hash never left in the clear", !leaked);
    }
    transport_tls.close(th);
    close(sv[0]);
    close(sv[1]);
}

int main(void) {
    test_exchange();
    test_long_password();
    test_wrong_credentials();
    test_server_closes_early();
    test_outer_handshake_failure();
    if (failed) {
        printf("%d check(s) failed\n", failed);
        return 1;
    }
    printf("trojan exchange ok\n");
    return 0;
}
