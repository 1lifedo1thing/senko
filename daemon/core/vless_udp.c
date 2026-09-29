#include "vless_udp.h"

#include <string.h>

static uint16_t read16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static void write16(uint8_t *p, uint16_t value) {
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static int valid_target(const vless_dest_t *target) {
    return target && target->port &&
        (target->atyp == VLESS_ADDR_IPV4 || target->atyp == VLESS_ADDR_IPV6);
}

static size_t address_size(vless_atyp_t atyp) {
    return atyp == VLESS_ADDR_IPV4 ? 4u : atyp == VLESS_ADDR_IPV6 ? 16u : 0u;
}

vless_udp_status_t vless_udp_init(vless_udp_t *codec, vless_udp_mode_t mode,
                                  const vless_dest_t *target) {
    if (!codec || !valid_target(target) ||
        (mode != VLESS_UDP_LENGTH && mode != VLESS_UDP_XUDP))
        return VLESS_UDP_ERR_ARG;
    memset(codec, 0, sizeof *codec);
    codec->mode = mode;
    codec->target = *target;
    return VLESS_UDP_OK;
}

vless_udp_status_t vless_udp_encode(vless_udp_t *codec,
                                    const uint8_t *payload, size_t payload_len,
                                    uint8_t *out, size_t cap, size_t *out_len) {
    if (out_len) *out_len = 0;
    if (!codec || !out || !out_len || !payload || payload_len == 0 ||
        payload_len > VLESS_UDP_PAYLOAD_MAX) return VLESS_UDP_ERR_ARG;
    size_t prefix = 2;
    if (codec->mode == VLESS_UDP_XUDP)
        prefix += (codec->sent_first ? 4u : 2u + 1u + 1u + 1u + 2u + 1u +
                   address_size(codec->target.atyp) + 8u) + 2u;
    if (prefix + payload_len > cap) return VLESS_UDP_ERR_SPACE;

    size_t pos = 0;
    if (codec->mode == VLESS_UDP_LENGTH) {
        write16(out, (uint16_t)payload_len);
        pos = 2;
    } else if (!codec->sent_first) {
        size_t addr_len = address_size(codec->target.atyp);
        size_t meta_len = 2u + 1u + 1u + 1u + 2u + 1u + addr_len + 8u;
        write16(out, (uint16_t)meta_len);
        pos = 2;
        write16(out + pos, 0); pos += 2;
        out[pos++] = 1;
        out[pos++] = 1;
        out[pos++] = 2;
        write16(out + pos, codec->target.port); pos += 2;
        out[pos++] = (uint8_t)codec->target.atyp;
        memcpy(out + pos, codec->target.host_addr, addr_len); pos += addr_len;
        memset(out + pos, 0, 8); pos += 8;
        write16(out + pos, (uint16_t)payload_len); pos += 2;
    } else {
        write16(out, 4); pos = 2;
        write16(out + pos, 0); pos += 2;
        out[pos++] = 2;
        out[pos++] = 1;
        write16(out + pos, (uint16_t)payload_len); pos += 2;
    }
    memcpy(out + pos, payload, payload_len);
    *out_len = pos + payload_len;
    codec->sent_first = 1;
    return VLESS_UDP_OK;
}

static vless_udp_status_t parse_xudp_meta(const vless_udp_t *codec,
                                           const uint8_t *meta, size_t meta_len,
                                           vless_dest_t *source) {
    if (meta_len < 4 || read16(meta) != 0 || meta[3] != 1)
        return VLESS_UDP_ERR_FRAME;
    *source = codec->target;
    if (meta[2] != 2) return VLESS_UDP_ERR_FRAME;
    if (meta_len == 4) return VLESS_UDP_OK;
    if (meta_len < 8 || meta[4] != 2) return VLESS_UDP_ERR_FRAME;
    size_t addr_len = address_size((vless_atyp_t)meta[7]);
    if (!addr_len || meta_len != 8u + addr_len) return VLESS_UDP_ERR_FRAME;
    source->port = read16(meta + 5);
    source->atyp = (vless_atyp_t)meta[7];
    memset(source->host_addr, 0, sizeof source->host_addr);
    memcpy(source->host_addr, meta + 8, addr_len);
    return source->port ? VLESS_UDP_OK : VLESS_UDP_ERR_FRAME;
}

vless_udp_status_t vless_udp_feed(vless_udp_t *codec, const uint8_t *input,
                                  size_t input_len, size_t *consumed,
                                  const uint8_t **payload, size_t *payload_len,
                                  vless_dest_t *source) {
    if (consumed) *consumed = 0;
    if (payload) *payload = NULL;
    if (payload_len) *payload_len = 0;
    if (source) memset(source, 0, sizeof *source);
    if (!codec || (!input && input_len) || !consumed || !payload ||
        !payload_len || !source) return VLESS_UDP_ERR_ARG;

    size_t required = 2;
    for (;;) {
        if (codec->pending_len >= required) {
            if (codec->mode == VLESS_UDP_LENGTH) {
                size_t length = read16(codec->pending);
                if (!length || length > VLESS_UDP_PAYLOAD_MAX)
                    return VLESS_UDP_ERR_FRAME;
                if (required == 2) { required = 2 + length; continue; }
                *payload = codec->pending + 2;
                *payload_len = length;
                *source = codec->target;
                codec->pending_len = 0;
                return VLESS_UDP_OK;
            }
            size_t meta_len = read16(codec->pending);
            if (meta_len < 4 || meta_len > 64) return VLESS_UDP_ERR_FRAME;
            size_t meta_end = 2 + meta_len;
            if (required == 2) { required = meta_end; continue; }
            const uint8_t *meta = codec->pending + 2;
            /* mux End, optionally flagged as an error, is how xray retires an
               idle or failed udp session; it carries no data */
            if (read16(meta) == 0 && meta[2] == 3 && (meta[3] & ~2u) == 0) {
                codec->pending_len = 0;
                return VLESS_UDP_END;
            }
            if (read16(meta) != 0 || (meta[2] != 2 && meta[2] != 4) ||
                (meta[3] != 0 && meta[3] != 1))
                return VLESS_UDP_ERR_FRAME;
            if (meta[3] == 0) {
                codec->pending_len = 0;
                return VLESS_UDP_SKIPPED;
            }
            size_t header = meta_end + 2;
            if (required == meta_end) { required = header; continue; }
            size_t length = read16(codec->pending + 2 + meta_len);
            if (length > VLESS_UDP_PAYLOAD_MAX || header + length > sizeof codec->pending)
                return VLESS_UDP_ERR_FRAME;
            if (!length) {
                codec->pending_len = 0;
                return VLESS_UDP_SKIPPED;
            }
            if (required == header) { required = header + length; continue; }
            if (meta[2] == 4) {
                codec->pending_len = 0;
                return VLESS_UDP_SKIPPED;
            }
            if (parse_xudp_meta(codec, codec->pending + 2, meta_len, source) !=
                VLESS_UDP_OK) return VLESS_UDP_ERR_FRAME;
            *payload = codec->pending + header;
            *payload_len = length;
            codec->pending_len = 0;
            return VLESS_UDP_OK;
        }
        if (*consumed == input_len) return VLESS_UDP_NEED_MORE;
        size_t need = required - codec->pending_len;
        size_t available = input_len - *consumed;
        size_t take = need < available ? need : available;
        memcpy(codec->pending + codec->pending_len, input + *consumed, take);
        codec->pending_len += take;
        *consumed += take;
    }
}
