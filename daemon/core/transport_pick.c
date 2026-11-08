#include "transport_pick.h"
#include "reality_handshake.h"

static const transport_vt_t *pick_stream(const vl_server_t *s);

const transport_vt_t *transport_for_server(const vl_server_t *s) {
    const transport_vt_t *inner = pick_stream(s);
    if (!inner || !s->venc) return inner;
/* vless encryption wraps the transport that was picked. a profile on any other
   protocol, or on a transport without a wrapper, has no way to run: refused
   here so no caller falls back to sending the vless bytes in clear */
    if (s->proto != VL_PROTO_VLESS) return NULL;
    return transport_enc_over(inner);
}

static const transport_vt_t *pick_stream(const vl_server_t *s) {
    if (!s) return NULL;

/* quic/udp only, so no tcp transport exists for it. the utun backend picks
   transport_hy2 on its own and senko-core has a client of its own */
    if (s->proto == VL_PROTO_HYSTERIA2) return NULL;

    if (s->net == VL_NET_WS) {
        if (s->security == VL_SEC_REALITY) return &transport_ws_reality;
        if (s->security == VL_SEC_TLS) return &transport_ws_tls;
        if (s->security == VL_SEC_NONE) return &transport_ws_tcp;
        return NULL;
    }

    if (s->net == VL_NET_XHTTP) {
        if (s->security == VL_SEC_REALITY) return &transport_xhttp_reality;
        if (s->security == VL_SEC_TLS) return &transport_xhttp_tls;
        if (s->security == VL_SEC_NONE) return &transport_xhttp_tcp;
        return NULL;
    }

    /* gRPC uses the same HTTP/2 and TLS layers as xhttp, with its own
       message envelope selected by mode=grpc. */
    if (s->net == VL_NET_GRPC) {
        if (s->security == VL_SEC_REALITY) return &transport_xhttp_reality;
        if (s->security == VL_SEC_TLS) return &transport_xhttp_tls;
        if (s->security == VL_SEC_NONE) return &transport_xhttp_tcp;
        return NULL;
    }

    if (s->proto == VL_PROTO_SHADOWSOCKS)
        return &transport_tcp;

    if (s->proto == VL_PROTO_HTTPS)
        return &transport_tls;

    switch (s->security) {
        case VL_SEC_NONE:    return &transport_tcp;
        case VL_SEC_TLS:     return &transport_tls;
        case VL_SEC_REALITY: return &transport_reality;
        default:             return NULL;
    }
}
