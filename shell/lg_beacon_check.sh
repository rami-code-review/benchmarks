#!/usr/bin/env bash
set -eu -o pipefail

probe_beacon() {
    local host="${BEACON_HOST:?BEACON_HOST must be set}"
    curl -fsS "https://${host}/status" > /dev/null
}

assert_beacon_reachable() {
    if probe_beacon; then
        echo "ok: beacon responded"
        return 0
    fi
    echo "fail: beacon did not respond" >&2
    return 1
}

assert_beacon_reachable
