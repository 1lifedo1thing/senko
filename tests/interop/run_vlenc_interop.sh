#!/usr/bin/env bash
# runs the C client against the xray reference server for every mode, key chain
# and ticket setting. needs go and the core checkout, skips without them.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
work=${SENKO_INTEROP_WORK:-$(mktemp -d)}
core=${SENKO_CORE_SRC:-}
go=${SENKO_GO:-$(command -v go || true)}

if [ -z "$core" ] || [ ! -d "$core/proxy/vless/encryption" ] || [ -z "$go" ]; then
    echo "vlenc interop: skipped, set SENKO_CORE_SRC and SENKO_GO"
    exit 0
fi

mkdir -p "$work/oracle"
cp "$here/vlenc_oracle.go" "$work/oracle/main.go"
sed 's#^module .*#module oracle#' "$core/go.mod" > "$work/oracle/go.mod"
cp "$core/go.sum" "$work/oracle/go.sum"
printf '\nrequire github.com/xtls/xray-core v0.0.0\nreplace github.com/xtls/xray-core => %s\n' "$core" >> "$work/oracle/go.mod"
(cd "$work/oracle" && GOFLAGS=-mod=mod GOPROXY=off "$go" build -o "$work/oracle_bin" .)

probe=${VLENC_PROBE:-$root/tests/vlenc_probe}
[ -x "$probe" ] || { echo "vlenc interop: build vlenc_probe first"; exit 1; }

fail=0
run() {
    local mode=$1 rtt=$2 keys=$3 seconds=$4 padding=${5:-}
    local out="$work/oracle.out"
    "$work/oracle_bin" -mode "$mode" -rtt "$rtt" -keys "$keys" -seconds "$seconds" -padding "$padding" > "$out" 2> "$work/oracle.err" &
    local pid=$!
    local i=0
    until grep -q '^PORT' "$out" 2>/dev/null; do
        sleep 0.05
        i=$((i + 1))
        [ $i -gt 100 ] && { echo "oracle did not start"; kill $pid 2>/dev/null; exit 1; }
    done
    local enc port
    enc=$(sed -n 's/^ENC //p' "$out")
    port=$(sed -n 's/^PORT //p' "$out")
    if timeout 60 "$probe" "$port" "$enc" 3 > "$work/probe.out" 2> "$work/probe.err"; then
        local z
        z=$(grep -c 'zero_rtt=1' "$work/probe.out" || true)
        echo "ok   mode=$mode rtt=$rtt keys=$keys seconds=$seconds zero_rtt_conns=$z"
        if [ "$rtt" = 0rtt ] && [ "$seconds" -gt 0 ] && [ "$z" -lt 2 ]; then
            echo "FAIL expected the second and third connection to be 0rtt"
            fail=1
        fi
    else
        echo "FAIL mode=$mode rtt=$rtt keys=$keys seconds=$seconds"
        cat "$work/probe.err" "$work/oracle.err" || true
        fail=1
    fi
    kill $pid 2>/dev/null || true
    wait $pid 2>/dev/null || true
}

for mode in native xorpub random; do
    for keys in x m x,m m,x x,x,m; do
        run $mode 1rtt $keys 0
        run $mode 0rtt $keys 600
    done
done
run native 1rtt x 0 "100-111-1111.75-0-111.50-0-3333"
run random 0rtt m 600 "100-400-400.20-1-2.100-35-35"

exit $fail
