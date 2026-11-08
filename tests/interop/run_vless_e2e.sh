#!/usr/bin/env bash
# end to end on the host: curl -> senkod socks5 -> vless encryption -> a real
# xray vless inbound -> a local http or https server. covers the loop, session,
# vision and the encryption transport together. needs go, curl, python3 and
# the core checkout; skips without them.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
work=${SENKO_INTEROP_WORK:-$(mktemp -d)}
core=${SENKO_CORE_SRC:-}
go=${SENKO_GO:-$(command -v go || true)}
senkod=${SENKOD:-$root/daemon/senkod}

if [ -z "$core" ] || [ ! -d "$core/proxy/vless/encryption" ] || [ -z "$go" ] ||
   ! command -v curl >/dev/null || ! command -v python3 >/dev/null; then
    echo "vless e2e: skipped, set SENKO_CORE_SRC and SENKO_GO and have curl and python3"
    exit 0
fi
[ -x "$senkod" ] || { echo "vless e2e: build daemon/senkod first"; exit 1; }

mkdir -p "$work/oracle" "$work/xray" "$work/www"
cp "$here/vlenc_oracle.go" "$work/oracle/main.go"
sed 's#^module .*#module oracle#' "$core/go.mod" > "$work/oracle/go.mod"
cp "$core/go.sum" "$work/oracle/go.sum"
printf '\nrequire github.com/xtls/xray-core v0.0.0\nreplace github.com/xtls/xray-core => %s\n' "$core" >> "$work/oracle/go.mod"
(cd "$work/oracle" && GOFLAGS=-mod=mod GOPROXY=off "$go" build -o "$work/keygen" .)
# the server is the stock full build of the pinned core, not the trimmed one
if [ ! -x "$work/xray_full" ]; then
    (cd "$core" && GOFLAGS=-mod=mod GOPROXY=off "$go" build -o "$work/xray_full" ./main)
fi

# a payload that spans many records, and a self signed tls site for vision
head -c 3000000 /dev/urandom > "$work/www/blob.bin"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
    -subj /CN=localhost -keyout "$work/key.pem" -out "$work/cert.pem" 2>/dev/null
cat > "$work/site.py" <<'PY'
import hashlib, http.server, ssl, sys, threading, functools
d = sys.argv[1]
class Handler(http.server.SimpleHTTPRequestHandler):
    # an upload answers with the sha256 of what arrived
    def do_POST(self):
        left = int(self.headers.get("Content-Length", "0"))
        h = hashlib.sha256()
        while left > 0:
            chunk = self.rfile.read(min(65536, left))
            if not chunk:
                break
            h.update(chunk)
            left -= len(chunk)
        body = h.hexdigest().encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
h = functools.partial(Handler, directory=d)
plain = http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[2])), h)
tls = http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[3])), h)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.load_cert_chain(sys.argv[4], sys.argv[5])
tls.socket = ctx.wrap_socket(tls.socket, server_side=True)
threading.Thread(target=plain.serve_forever, daemon=True).start()
tls.serve_forever()
PY
site_plain=$((20000 + RANDOM % 5000)); site_tls=$((site_plain + 1))
xray_port=$((26000 + RANDOM % 3000)); socks=$((30000 + RANDOM % 3000))
python3 "$work/site.py" "$work/www" $site_plain $site_tls "$work/cert.pem" "$work/key.pem" > "$work/site.log" 2>&1 &
pids="$!"
cleanup() { kill $pids 2>/dev/null || true; wait 2>/dev/null || true; }
trap cleanup EXIT

uuid=11111111-1111-4111-8111-111111111111
want=$(sha256sum "$work/www/blob.bin" | cut -d' ' -f1)
fail=0

run() {
    local mode=$1 keys=$2 flow=$3 rtt=$4 padding=${5:-}
    local gen enc dec
    gen=$("$work/keygen" -gen -mode "$mode" -rtt "$rtt" -keys "$keys" -seconds 600 -padding "$padding")
    enc=$(sed -n 's/^ENC //p' <<<"$gen")
    dec=$(sed -n 's/^DEC //p' <<<"$gen")
    cat > "$work/xray.json" <<JSON
{"log":{"loglevel":"warning"},
 "inbounds":[{"listen":"127.0.0.1","port":$xray_port,"protocol":"vless",
   "settings":{"clients":[{"id":"$uuid","flow":"$flow"}],"decryption":"$dec"},
   "streamSettings":{"network":"tcp"}}],
 "outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow"}]}}]}
JSON
    "$work/xray_full" run -c "$work/xray.json" > "$work/xray.log" 2>&1 &
    local xp=$!
    local i=0
    until (exec 3<>/dev/tcp/127.0.0.1/$xray_port) 2>/dev/null; do
        sleep 0.1; i=$((i + 1))
        [ $i -gt 100 ] && { echo "xray did not start"; cat "$work/xray.log"; kill $xp; exit 1; }
    done
    local link="vless://$uuid@127.0.0.1:$xray_port?security=none&type=tcp&encryption=$enc"
    [ -n "$flow" ] && link="$link&flow=$flow"
    "$senkod" "$link" $socks > "$work/senkod.log" 2>&1 &
    local sp=$!
    i=0
    until (exec 3<>/dev/tcp/127.0.0.1/$socks) 2>/dev/null; do
        sleep 0.1; i=$((i + 1))
        [ $i -gt 50 ] && { echo "senkod did not start"; cat "$work/senkod.log"; kill $xp $sp; exit 1; }
    done
    local got1 got2 got3
    got1=$(curl -sS --max-time 60 --socks5-hostname 127.0.0.1:$socks "http://127.0.0.1:$site_plain/blob.bin" 2>"$work/curl1.err" | sha256sum | cut -d' ' -f1)
    got2=$(curl -sSk --max-time 60 --socks5-hostname 127.0.0.1:$socks "https://127.0.0.1:$site_tls/blob.bin" 2>"$work/curl2.err" | sha256sum | cut -d' ' -f1)
    # an upload through the tls site: the vision switch happens early, the megabytes after it go up as plain inner records
    local up
    up=$(curl -sSk --max-time 60 --socks5-hostname 127.0.0.1:$socks --data-binary "@$work/www/blob.bin" "https://127.0.0.1:$site_tls/up" 2>"$work/curl5.err")
    # a second pass, so the 0rtt ticket the first one earned gets used
    got3=$(curl -sS --max-time 60 --socks5-hostname 127.0.0.1:$socks "http://127.0.0.1:$site_plain/blob.bin" 2>"$work/curl3.err" | sha256sum | cut -d' ' -f1)
    if [ "$got1" = "$want" ] && [ "$got2" = "$want" ] && [ "$got3" = "$want" ] && [ "$up" = "$want" ]; then
        echo "ok   mode=$mode keys=$keys flow=${flow:-none} rtt=$rtt"
    else
        echo "FAIL mode=$mode keys=$keys flow=${flow:-none} rtt=$rtt (plain=$([ "$got1" = "$want" ] && echo ok || echo bad) tls=$([ "$got2" = "$want" ] && echo ok || echo bad) again=$([ "$got3" = "$want" ] && echo ok || echo bad) upload=$([ "$up" = "$want" ] && echo ok || echo bad))"
        cat "$work/curl1.err" "$work/curl2.err" "$work/curl3.err" "$work/curl5.err" || true
        tail -20 "$work/senkod.log" || true
        tail -20 "$work/xray.log" || true
        fail=1
    fi
    kill $sp $xp 2>/dev/null || true
    wait $sp $xp 2>/dev/null || true
}

# the pinned core itself: a socks inbound in front of the outbound that
# senko_core_config.c renders, trimmed build (tag senko_trim) as the client
core_run() {
    local mode=$1 keys=$2 flow=$3
    local render=${SENKO_CORE_RENDER:-$root/tests/senko_core_render}
    [ -x "$render" ] || { echo "skip core stage: build tests/senko_core_render"; return 0; }
    if [ ! -x "$work/xray_trim" ]; then
        (cd "$core" && GOFLAGS=-mod=mod GOPROXY=off "$go" build -tags senko_trim -o "$work/xray_trim" ./main)
    fi
    local gen enc dec
    gen=$("$work/keygen" -gen -mode "$mode" -rtt 0rtt -keys "$keys" -seconds 600)
    enc=$(sed -n 's/^ENC //p' <<<"$gen")
    dec=$(sed -n 's/^DEC //p' <<<"$gen")
    cat > "$work/xray.json" <<JSON
{"log":{"loglevel":"warning"},
 "inbounds":[{"listen":"127.0.0.1","port":$xray_port,"protocol":"vless",
   "settings":{"clients":[{"id":"$uuid","flow":"$flow"}],"decryption":"$dec"},
   "streamSettings":{"network":"tcp"}}],
 "outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow"}]}}]}
JSON
    local link="vless://$uuid@127.0.0.1:$xray_port?security=none&type=tcp&encryption=$enc"
    [ -n "$flow" ] && link="$link&flow=$flow"
    "$render" "$link" 127.0.0.1 > "$work/rendered.json"
    python3 - "$work/rendered.json" "$work/core_client.json" "$socks" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
c["inbounds"] = [{"listen": "127.0.0.1", "port": int(sys.argv[3]), "protocol": "socks", "settings": {"udp": False}}]
c["outbounds"] = [o for o in c["outbounds"] if o.get("tag") == "senko-out"]
c.pop("routing", None)
json.dump(c, open(sys.argv[2], "w"))
PY
    "$work/xray_full" run -c "$work/xray.json" > "$work/xray.log" 2>&1 &
    local xp=$!
    "$work/xray_trim" run -c "$work/core_client.json" > "$work/core.log" 2>&1 &
    local cp=$!
    local i=0
    until (exec 3<>/dev/tcp/127.0.0.1/$socks) 2>/dev/null; do
        sleep 0.1; i=$((i + 1))
        [ $i -gt 100 ] && { echo "core did not start"; cat "$work/core.log"; kill $xp $cp; exit 1; }
    done
    local got
    got=$(curl -sS --max-time 60 --socks5-hostname 127.0.0.1:$socks "http://127.0.0.1:$site_plain/blob.bin" 2>"$work/curl4.err" | sha256sum | cut -d' ' -f1)
    if [ "$got" = "$want" ]; then
        echo "ok   core mode=$mode keys=$keys flow=${flow:-none}"
    else
        echo "FAIL core mode=$mode keys=$keys flow=${flow:-none}"
        cat "$work/curl4.err" "$work/core.log" "$work/xray.log" || true
        fail=1
    fi
    kill $cp $xp 2>/dev/null || true
    wait $cp $xp 2>/dev/null || true
}

for mode in native xorpub random; do
    for keys in x m x,m; do
        run $mode $keys "" 0rtt
        run $mode $keys xtls-rprx-vision 0rtt
    done
done
core_run native x ""
core_run native x,m xtls-rprx-vision
core_run random m xtls-rprx-vision
run native x xtls-rprx-vision 1rtt
run random m xtls-rprx-vision 1rtt "100-300-600.20-1-2.100-35-60"
exit $fail
